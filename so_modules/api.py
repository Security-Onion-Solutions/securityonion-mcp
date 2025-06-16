# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import asyncio
import json
import requests
import urllib.parse # Added for urljoin
import logging
from . import config # Use relative import within the package

async def get_so_token() -> str:
    """Helper function to retrieve the Security Onion API access token."""
    # Use config variables directly
    if not all([config.SO_CLIENT_ID, config.SO_CLIENT_SECRET, config.SO_API_ENDPOINT]):
        # Check config at the start or rely on caller to check? Let's check here for robustness.
        config.check_config() # This will raise ValueError if missing

    token_url = f"{config.SO_API_ENDPOINT}/oauth2/token"
    auth = (config.SO_CLIENT_ID, config.SO_CLIENT_SECRET)
    data = {"grant_type": "client_credentials"}

    try:
        # Determine the verify parameter for requests
        verify_param = config.SO_CA_CERT if config.SO_CA_CERT else config.SO_API_VERIFY_SSL

        # Note: verify=False mirrors curl -k. Consider addressing certificate issues.
        response = await asyncio.to_thread(requests.post, token_url, auth=auth, data=data, verify=verify_param)
        response.raise_for_status()
        token_data = response.json()
        if "access_token" not in token_data:
             raise KeyError("access_token not found in response")
        return token_data["access_token"]
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to get SO API token. Request error: {e}")
        raise Exception("Failed to retrieve Security Onion API token due to a network or request error.")
    except json.JSONDecodeError as e: # Catch JSONDecodeError specifically
        # Log the detailed error including the response text that failed parsing
        logging.error(f"Failed to parse SO API token response. Error: {e}. Response text: {response.text}")
        raise Exception("Received an invalid response when retrieving Security Onion API token.")
    # Note: The explicit KeyError raise on line 29 handles missing 'access_token'.


async def make_so_api_request(endpoint_path: str, params: dict) -> dict:
    """Helper function to make a GET request to the Security Onion API."""
    if not config.SO_API_ENDPOINT:
        config.check_config() # Ensure endpoint is loaded

    access_token = await get_so_token()
    headers = {"Authorization": f"Bearer {access_token}"}
    # Use urljoin to correctly handle potential trailing/leading slashes
    url = urllib.parse.urljoin(config.SO_API_ENDPOINT, endpoint_path)

    # Ensure default params are present if not provided
    # TODO: These defaults might be better placed in the tool logic that calls this function
    params.setdefault("zone", "America/New_York") # TODO: Make configurable
    params.setdefault("format", "2006/01/02 3:04:05 PM") # TODO: Make configurable
    params.setdefault("metricLimit", "10")
    params.setdefault("eventLimit", "10")

    try:
        # Determine the verify parameter for requests
        verify_param = config.SO_CA_CERT if config.SO_CA_CERT else config.SO_API_VERIFY_SSL

        # Note: verify=False mirrors curl -k.
        response = await asyncio.to_thread(requests.get, url, headers=headers, params=params, verify=verify_param)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle general request errors (connection, timeout, etc.)
        logging.error(f"SO API request failed for endpoint '{endpoint_path}'. Request error: {e}")
        raise Exception(f"Security Onion API request failed for endpoint '{endpoint_path}' due to a network or request error.")
    except json.JSONDecodeError:
        # Handle cases where the response is not valid JSON
        # Log the detailed error including the response text that failed parsing
        logging.error(f"Failed to parse SO API response for endpoint '{endpoint_path}'. Response text: {response.text}")
        raise Exception(f"Received an invalid response from Security Onion API endpoint '{endpoint_path}'.")
# Removed duplicate exception handler