# hubspot.py
import os
from fastapi import Request
from dotenv import load_dotenv
from pathlib import Path
import base64
import json
import secrets
import httpx
import asyncio
import hashlib
from fastapi import HTTPException
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem
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
    
    # Store state in Redis for later validation
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
    )

    return authorization_url

async def oauth2callback_hubspot(request: Request):
    # TODO
    pass

async def get_hubspot_credentials(user_id, org_id):
    # TODO
    pass

async def create_integration_item_metadata_object(response_json):
    # TODO
    pass

async def get_items_hubspot(credentials):
    # TODO
    pass