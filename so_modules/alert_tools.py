# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import asyncio
import json
import requests
import urllib.parse
import logging
from typing import Optional, Dict, Any
from . import config

logger = logging.getLogger(__name__)


async def acknowledge_alerts_impl(
    acknowledge: bool = True,
    search_filter: Optional[str] = None,
    event_filter: Optional[Dict[str, str]] = None,
    date_range: Optional[str] = None,
    date_range_format: Optional[str] = None,
    timezone: Optional[str] = None,
    escalate: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Acknowledge or unacknowledge alert events matching the given criteria.
    
    Args:
        acknowledge: Whether to acknowledge (True) or unacknowledge (False) the events.
        search_filter: OQL search filter to find matching events (e.g., "tags:alert AND rule.uuid:xyz").
        event_filter: Optional dict of field:value pairs to further filter events.
        date_range: Date range for searching events (e.g., "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM").
        date_range_format: Format of the date range (default: "2006/01/02 3:04:05 PM").
        timezone: Timezone for date range (default: "America/New_York").
        escalate: Whether events have been escalated to a case.
    
    Returns:
        Dictionary containing update results including:
        - updated: Number of events updated
        - failed: Number of events that failed to update
        - errors: List of any errors encountered
        - completeTime: When the operation completed
        - elapsedMs: How long the operation took
    """
    # Get token using existing API module function
    from . import api
    
    # Build request body
    body = {
        "acknowledge": acknowledge
    }
    
    # Add optional parameters
    if search_filter:
        body["searchFilter"] = search_filter
    if event_filter:
        body["eventFilter"] = event_filter
    if date_range:
        body["dateRange"] = date_range
    if date_range_format:
        body["dateRangeFormat"] = date_range_format
    else:
        body["dateRangeFormat"] = "2006/01/02 3:04:05 PM"  # Default format
    if timezone:
        body["timezone"] = timezone
    else:
        body["timezone"] = "America/New_York"  # Default timezone
    if escalate is not None:
        body["escalate"] = escalate
    
    try:
        # Get access token
        access_token = await api.get_so_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # Build URL
        url = urllib.parse.urljoin(config.SO_API_ENDPOINT, "/connect/events/ack")
        
        # Determine the verify parameter
        verify_param = config.SO_CA_CERT if config.SO_CA_CERT else config.SO_API_VERIFY_SSL
        
        # Make POST request
        response = await asyncio.to_thread(
            requests.post,
            url,
            headers=headers,
            json=body,
            verify=verify_param
        )
        
        # Check for errors
        if response.status_code == 400:
            return {
                "error": "Invalid input parameters",
                "details": response.text
            }
        elif response.status_code == 401:
            return {
                "error": "Authentication failed",
                "details": "Request was not properly authenticated"
            }
        elif response.status_code == 405:
            return {
                "error": "Event module not loaded",
                "details": "The event module is not loaded on the server"
            }
        elif response.status_code == 500:
            return {
                "error": "Internal server error",
                "details": "Internal SOC error; review SOC logs"
            }
        
        response.raise_for_status()
        
        # Parse and return results
        result = response.json()
        
        # Log summary
        updated = result.get("updated", 0)
        failed = result.get("failed", 0)
        action = "acknowledged" if acknowledge else "unacknowledged"
        logger.info(f"Alert acknowledgment complete: {updated} events {action}, {failed} failed")
        
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to acknowledge alerts: {e}")
        return {
            "error": "Request failed",
            "details": str(e)
        }
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse response: {e}")
        return {
            "error": "Invalid response format",
            "details": str(e)
        }
    except Exception as e:
        logger.error(f"Unexpected error acknowledging alerts: {e}")
        return {
            "error": "Unexpected error",
            "details": str(e)
        }