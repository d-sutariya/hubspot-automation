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
import logging

# Configure logger
logger = logging.getLogger(__name__)

load_dotenv(Path(__file__).parents[1]/'.env')

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI')

# HubSpot scopes - adjust based on your app's requirements
SCOPES = os.getenv('HUBSPOT_SCOPE', 'crm.objects.contacts.read crm.objects.contacts.write crm.objects.companies.read crm.objects.companies.write crm.objects.deals.read crm.objects.deals.write')
async def authorize_hubspot(user_id, org_id):
    logger.info(f"Starting HubSpot authorization for user_id: {user_id}, org_id: {org_id}")
    
    # Create state data for OAuth security
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    logger.info(f"Generated OAuth state for user {user_id}")
    
    # Build HubSpot authorization URL 
    authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}&state={encoded_state}'
    logger.info(f"Built authorization URL for user {user_id}")
    
    # Store encoded state in Redis for later validation
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', encoded_state, expire=600),
    )
    logger.info(f"Stored OAuth state in Redis for user {user_id} with 10 minute expiry")

    return authorization_url

async def oauth2callback_hubspot(request: Request):
    logger.info("HubSpot OAuth callback initiated")
    
    # Extract code and state from query parameters
    code = request.query_params.get('code')
    state_param = request.query_params.get('state')
    
    logger.info(f"Received OAuth callback with code: {'present' if code else 'missing'}, state: {'present' if state_param else 'missing'}")
    
    if not code:
        logger.error("Authorization code not found in callback")
        raise HTTPException(status_code=400, detail="Authorization code not found")
    
    if not state_param:
        logger.error("State parameter not found in callback")
        raise HTTPException(status_code=400, detail="State parameter not found")
    
    try:
        # Decode the state parameter to get user and org info for Redis lookup
        decoded_state = base64.urlsafe_b64decode(state_param.encode('utf-8')).decode('utf-8')
        state_data = json.loads(decoded_state)
        
        user_id = state_data.get('user_id')
        org_id = state_data.get('org_id')
        
        logger.info(f"Decoded state for user_id: {user_id}, org_id: {org_id}")
        
        if not user_id or not org_id:
            logger.error("Invalid state data - missing user_id or org_id")
            raise HTTPException(status_code=400, detail="Invalid state data")
        
        # Get stored encoded state from Redis
        stored_encoded_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
        if not stored_encoded_state:
            logger.error(f"State verification failed - no stored state found for user {user_id}")
            raise HTTPException(status_code=400, detail="State verification failed - session expired")
        
        # Direct comparison of encoded states 
        if stored_encoded_state.decode() != state_param:
            logger.error(f"State verification failed - state mismatch for user {user_id}")
            raise HTTPException(status_code=400, detail="State verification failed - invalid state")
        
        logger.info(f"State verification successful for user {user_id}")
        
        # Prepare token exchange request
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
        
        logger.info(f"Initiating token exchange with HubSpot for user {user_id}")
        
        # Exchange authorization code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                'https://api.hubapi.com/oauth/v1/token',
                headers={'content-type': 'application/x-www-form-urlencoded'},
                data=token_data
            )
        
        logger.info(f"Token exchange response status: {response.status_code} for user {user_id}")
        
        if response.status_code != 200:
            logger.error(f"Token exchange failed for user {user_id}: {response.text}")
            raise HTTPException(
                status_code=400, 
                detail=f"Token exchange failed: {response.text}"
            )
        
        token_response = response.json()
        logger.info(f"Successfully obtained access token for user {user_id}")
        
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
        
        logger.info(f"Stored credentials in Redis for user {user_id} with 30-day expiry")
        
        # Clean up temporary state data
        await delete_key_redis(f'hubspot_state:{org_id}:{user_id}')
        logger.info(f"Cleaned up temporary OAuth state for user {user_id}")
        
        close_window_script = """
        <html>
            <script>
                window.close();
            </script>
        </html>
        """
        logger.info(f"HubSpot OAuth flow completed successfully for user {user_id}")
        return HTMLResponse(content=close_window_script)
        
    except json.JSONDecodeError:
        logger.error("Failed to decode state parameter - invalid JSON")
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    except Exception as e:
        logger.error(f"OAuth callback failed with exception: {str(e)}")
        raise HTTPException(status_code=500, detail=f"OAuth callback failed: {str(e)}")

async def get_hubspot_credentials(user_id, org_id):
    """Retrieve HubSpot credentials from Redis storage with automatic token refresh"""
    logger.info(f"Retrieving HubSpot credentials for user_id: {user_id}, org_id: {org_id}")
    
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    
    if not credentials:
        logger.error(f"No HubSpot credentials found for user {user_id}")
        raise HTTPException(status_code=400, detail='No HubSpot credentials found. Please re-authorize the integration.')
    
    try:
        credentials_data = json.loads(credentials.decode() if isinstance(credentials, bytes) else credentials)
        logger.info(f"Successfully parsed credentials for user {user_id}")
    except json.JSONDecodeError:
        logger.error(f"Invalid credentials format for user {user_id}")
        raise HTTPException(status_code=400, detail='Invalid credentials format. Please re-authorize the integration.')
    
    if not credentials_data:
        logger.error(f"Empty credentials found for user {user_id}")
        raise HTTPException(status_code=400, detail='Empty credentials found. Please re-authorize the integration.')
    
    # Check if token is expired or about to expire (refresh 5 minutes before expiry)
    current_timestamp = int(time.time())
    expires_at = credentials_data.get('expires_at', 0)
    buffer_time = 300  # 5 minutes buffer
    
    logger.info(f"Token check for user {user_id}: current={current_timestamp}, expires_at={expires_at}, needs_refresh={current_timestamp >= (expires_at - buffer_time)}")
    
    if current_timestamp >= (expires_at - buffer_time):
        # Token is expired or about to expire, refresh it
        logger.info(f"Token expired/expiring for user {user_id}, attempting refresh")
        try:
            refreshed_credentials = await refresh_hubspot_token(credentials_data['refresh_token'], user_id, org_id)
            logger.info(f"Successfully refreshed token for user {user_id}")
            return refreshed_credentials
        except Exception as e:
            logger.error(f"Token refresh failed for user {user_id}: {str(e)}")
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
    logger.info(f"Using valid existing token for user {user_id}")
    return credentials_data

async def refresh_hubspot_token(refresh_token, user_id, org_id):
    """Refresh HubSpot access token using refresh token"""
    logger.info(f"Starting token refresh for user {user_id}")
    
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
    
    logger.info(f"Token refresh response status: {response.status_code} for user {user_id}")
    
    if response.status_code != 200:
        logger.error(f"Token refresh failed for user {user_id}: {response.text}")
        raise HTTPException(
            status_code=400, 
            detail=f"Token refresh failed: {response.text}"
        )
    
    token_response = response.json()
    logger.info(f"Successfully refreshed token for user {user_id}")
    
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
    
    logger.info(f"Updated refreshed credentials in Redis for user {user_id}")
    return refreshed_credentials

async def create_integration_item_metadata_object(response_json, object_type="company"):
    """Create an IntegrationItem from HubSpot object response"""
    properties = response_json.get('properties', {})
    
    # Extract name based on object type
    if object_type == "company":
        name = properties.get('name') or properties.get('domain') or f"Company {response_json.get('id')}"
    elif object_type == "contact":
        firstname = properties.get('firstname', '')
        lastname = properties.get('lastname', '')
        email = properties.get('email', '')
        name = f"{firstname} {lastname}".strip() or email or f"Contact {response_json.get('id')}"
    elif object_type == "deal":
        name = properties.get('dealname') or f"Deal {response_json.get('id')}"
    else:
        name = f"{object_type.title()} {response_json.get('id')}"
    
    integration_item = IntegrationItem(
        id=response_json.get('id'),
        type=object_type,
        name=name,
        creation_time=response_json.get('createdAt'),
        last_modified_time=response_json.get('updatedAt'),
        parent_id=None  # HubSpot objects typically don't have parent-child relationships
    )
    
    return integration_item

async def get_items_hubspot(credentials_data):
    """Fetch HubSpot objects (companies, contacts, deals) and return as IntegrationItems"""
    logger.info("Starting HubSpot data fetch process")
    
    try:
        logger.info(f"Received credentials_data type: {type(credentials_data)}")
        
        # credentials_data is already a dictionary from get_hubspot_credentials
        if isinstance(credentials_data, dict):
            logger.info("Using credentials dictionary directly")
        else:
            try:
                credentials_data = json.loads(credentials_data)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Invalid JSON in credentials: {str(e)}")
        
        access_token = credentials_data.get('access_token')
        
        if not access_token:
            logger.error("No access token found in credentials")
            raise HTTPException(status_code=400, detail="No access token found in credentials")
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        list_of_integration_items = []
        
        # Fetch all object types concurrently for better performance
        logger.info("Starting concurrent fetch of HubSpot companies, contacts, and deals")
        
        await asyncio.gather(
            fetch_hubspot_objects(
                'companies', 
                headers, 
                list_of_integration_items,
                properties=['name', 'domain', 'industry', 'city', 'state']
            ),
            fetch_hubspot_objects(
                'contacts', 
                headers, 
                list_of_integration_items,
                properties=['firstname', 'lastname', 'email', 'phone', 'company']
            ),
            fetch_hubspot_objects(
                'deals', 
                headers, 
                list_of_integration_items,
                properties=['dealname', 'amount', 'dealstage', 'pipeline', 'closedate']
            )
        )
        
        logger.info(f"Successfully fetched {len(list_of_integration_items)} total HubSpot items concurrently")
        return list_of_integration_items
        
    except Exception as e:
        logger.error(f"Failed to fetch HubSpot data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch HubSpot data: {str(e)}")

async def fetch_hubspot_objects(object_type, headers, integration_items_list, properties=None, limit=100):
    """Fetch objects from HubSpot using the search API with pagination"""
    logger.info(f"Starting fetch for HubSpot {object_type}")
    
    url = f'https://api.hubapi.com/crm/v3/objects/{object_type}/search'
    
    if properties is None:
        if object_type == 'companies':
            properties = ['name']
        elif object_type == 'contacts':
            properties = ['firstname', 'lastname']
        else:
            properties = ['dealname']

    logger.info(f"Fetching {object_type} with properties: {properties}")
    
    after = None
    page_count = 0
    max_pages = 50  # Limit to prevent long loops
    total_items = 0
    
    async with httpx.AsyncClient() as client:
        while page_count < max_pages:
            logger.info(f"Fetching {object_type} page {page_count + 1}")
            
            # Build search payload
            search_payload = {
                "limit": limit,
                "properties": properties,
                "filterGroups": [],  # Empty filter to get all objects
                "sorts": [{"propertyName": "createdate", "direction": "DESCENDING"}]
            }
            
            if after:
                search_payload["after"] = after
            
            try:
                response = await client.post(url, headers=headers, json=search_payload)
                
                logger.info(f"{object_type} page {page_count + 1} response status: {response.status_code}")
                
                if response.status_code != 200:
                    logger.error(f"Failed to fetch {object_type} page {page_count + 1}: {response.status_code} - {response.text}")
                    break
                
                data = response.json()
                results = data.get('results', [])
                
                logger.info(f"Retrieved {len(results)} {object_type} items on page {page_count + 1}")
                
                # Convert each result to IntegrationItem
                for item in results:
                    integration_item = await create_integration_item_metadata_object(item, object_type.rstrip('s') if object_type != 'companies' else 'company')
                    integration_items_list.append(integration_item)
                    total_items += 1
                
                # Check for pagination
                paging = data.get('paging', {})
                after = paging.get('next', {}).get('after')
                
                logger.info(f"{object_type} page {page_count + 1}: has_more_pages={bool(after)}")
                
                if not after or len(results) < limit:
                    break  # No more pages
                    
                page_count += 1
                
            except Exception as e:
                logger.error(f"Error fetching {object_type} page {page_count + 1}: {str(e)}")
                break
    
    logger.info(f"Completed fetching {object_type}: {total_items} items across {page_count + 1} pages")