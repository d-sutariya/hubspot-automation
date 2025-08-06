# hubspot.py
import os
from fastapi import Request
from dotenv import load_dotenv
from pathlib import Path
import base64
import json
import secrets
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import hashlib
from fastapi import HTTPException
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem
import time

load_dotenv(Path(__file__).parents[1]/'.env')

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI')

# HubSpot scopes - adjust based on your app's requirements
SCOPES = os.getenv('HUBSPOT_SCOPE', 'crm.objects.contacts.read crm.objects.contacts.write crm.objects.companies.read crm.objects.companies.write crm.objects.deals.read crm.objects.deals.write')
async def authorize_hubspot(user_id, org_id):
    # Create state data for OAuth security
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    
    # Build HubSpot authorization URL 
    authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}&state={encoded_state}'
    
    # Store encoded state in Redis for later validation
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', encoded_state, expire=600),
    )

    return authorization_url

async def oauth2callback_hubspot(request: Request):
    # Extract code and state from query parameters
    code = request.query_params.get('code')
    state_param = request.query_params.get('state')
    
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")
    
    if not state_param:
        raise HTTPException(status_code=400, detail="State parameter not found")
    
    try:
        # Decode the state parameter to get user and org info for Redis lookup
        decoded_state = base64.urlsafe_b64decode(state_param.encode('utf-8')).decode('utf-8')
        state_data = json.loads(decoded_state)
        
        user_id = state_data.get('user_id')
        org_id = state_data.get('org_id')
        
        if not user_id or not org_id:
            raise HTTPException(status_code=400, detail="Invalid state data")
        
        # Get stored encoded state from Redis
        stored_encoded_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
        if not stored_encoded_state:
            raise HTTPException(status_code=400, detail="State verification failed - session expired")
        
        # Direct comparison of encoded states 
        if stored_encoded_state.decode() != state_param:
            raise HTTPException(status_code=400, detail="State verification failed - invalid state")
        
        # Prepare token exchange request
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
        
        # Exchange authorization code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                'https://api.hubapi.com/oauth/v1/token',
                headers={'content-type': 'application/x-www-form-urlencoded'},
                data=token_data
            )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=400, 
                detail=f"Token exchange failed: {response.text}"
            )
        
        token_response = response.json()
        
        # Store the tokens securely in Redis with expiration and metadata
        
        current_timestamp = int(time.time())
        expires_at = current_timestamp + token_response.get('expires_in', 1800)
        
        credentials = {
            'access_token': token_response['access_token'],
            'refresh_token': token_response['refresh_token'],
            'token_type': token_response.get('token_type', 'bearer'),
            'expires_in': token_response.get('expires_in', 1800),
            'expires_at': expires_at,
            'created_at': current_timestamp,
            'status': 'active'
        }
        
        # Store credentials in Redis with longer expiration (30 days for persistent access)
        await add_key_value_redis(
            f'hubspot_credentials:{org_id}:{user_id}', 
            json.dumps(credentials), 
            expire=2592000  # 30 days
        )
        
        # Clean up temporary state data
        await delete_key_redis(f'hubspot_state:{org_id}:{user_id}')
        close_window_script = """
        <html>
            <script>
                window.close();
            </script>
        </html>
        """
        return HTMLResponse(content=close_window_script)
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth callback failed: {str(e)}")

async def get_hubspot_credentials(user_id, org_id):
    """Retrieve HubSpot credentials from Redis storage with automatic token refresh"""
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    
    if not credentials:
        raise HTTPException(status_code=400, detail='No HubSpot credentials found. Please re-authorize the integration.')
    
    try:
        credentials_data = json.loads(credentials.decode() if isinstance(credentials, bytes) else credentials)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail='Invalid credentials format. Please re-authorize the integration.')
    
    if not credentials_data:
        raise HTTPException(status_code=400, detail='Empty credentials found. Please re-authorize the integration.')
    
    # Check if token is expired or about to expire (refresh 5 minutes before expiry)
    current_timestamp = int(time.time())
    expires_at = credentials_data.get('expires_at', 0)
    buffer_time = 300  # 5 minutes buffer
    
    if current_timestamp >= (expires_at - buffer_time):
        # Token is expired or about to expire, refresh it
        try:
            refreshed_credentials = await refresh_hubspot_token(credentials_data['refresh_token'], user_id, org_id)
            return refreshed_credentials
        except Exception as e:
            # If refresh fails, mark as expired and ask for re-authorization
            credentials_data['status'] = 'expired'
            await add_key_value_redis(
                f'hubspot_credentials:{org_id}:{user_id}', 
                json.dumps(credentials_data), 
                expire=2592000
            )
            raise HTTPException(
                status_code=401, 
                detail='HubSpot token expired and refresh failed. Please re-authorize the integration.'
            )
    
    # Token is still valid
    credentials_data['status'] = 'active'
    return credentials_data

async def refresh_hubspot_token(refresh_token, user_id, org_id):
    """Refresh HubSpot access token using refresh token"""
    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            'https://api.hubapi.com/oauth/v1/token',
            headers={'content-type': 'application/x-www-form-urlencoded'},
            data=token_data
        )
    
    if response.status_code != 200:
        raise HTTPException(
            status_code=400, 
            detail=f"Token refresh failed: {response.text}"
        )
    
    token_response = response.json()
    
    # Store refreshed credentials
    current_timestamp = int(time.time())
    expires_at = current_timestamp + token_response.get('expires_in', 1800)
    
    refreshed_credentials = {
        'access_token': token_response['access_token'],
        'refresh_token': token_response.get('refresh_token', refresh_token),  # Some APIs don't return new refresh token
        'token_type': token_response.get('token_type', 'bearer'),
        'expires_in': token_response.get('expires_in', 1800),
        'expires_at': expires_at,
        'refreshed_at': current_timestamp,
        'status': 'active'
    }
    
    # Update stored credentials
    await add_key_value_redis(
        f'hubspot_credentials:{org_id}:{user_id}', 
        json.dumps(refreshed_credentials), 
        expire=2592000  # 30 days
    )
    
    return refreshed_credentials

async def create_integration_item_metadata_object(response_json):
    # TODO
    pass

async def get_items_hubspot(credentials):
    # TODO
    pass