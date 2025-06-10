# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Playbook tools for Security Onion MCP server.
Handles playbook execution for alerts, including fetching playbooks and running queries.
"""

import logging
import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from . import api
from . import utils
from . import event_query_tools

logger = logging.getLogger(__name__)


async def get_playbooks_for_detection(detection_id: str) -> List[Dict[str, Any]]:
    """
    Fetch playbooks associated with a specific detection/alert ID.
    
    Args:
        detection_id: The public ID of the detection/alert
        
    Returns:
        List of playbook dictionaries
    """
    endpoint = f"/connect/playbook/detection/{detection_id}"
    
    try:
        # make_so_api_request doesn't take a method parameter, it's always GET
        response = await api.make_so_api_request(endpoint, params={})
        return response if isinstance(response, list) else []
    except Exception as e:
        logger.error(f"Failed to fetch playbooks for detection {detection_id}: {e}")
        raise


def _substitute_variables(query: str, alert_data: Dict[str, Any]) -> str:
    """
    Replace variables in a Sigma query with values from the alert.
    Variables are in the format {{field.name}}, {field.name}, or $field.name
    
    Args:
        query: The Sigma query with variables
        alert_data: The alert data containing field values
        
    Returns:
        Query with variables replaced
    """
    # Handle {{field.name}} format (double braces)
    pattern = r'\{\{([^}]+)\}\}'
    
    def replace_match(match):
        field_path = match.group(1).strip()
        value = utils.get_nested_field(alert_data, field_path)
        if value is None:
            logger.warning(f"Field {field_path} not found in alert data")
            return match.group(0)  # Keep original if not found
        
        # Escape the value for OQL
        return utils.escape_oql_value(str(value))
    
    query = re.sub(pattern, replace_match, query)
    
    # Handle {field.name} format (single braces)
    # Use negative lookbehind/lookahead to avoid matching already processed {{}}
    pattern = r'(?<!\{)\{([^{}]+)\}(?!\})'
    
    def replace_single_brace_match(match):
        field_path = match.group(1).strip()
        value = utils.get_nested_field(alert_data, field_path)
        if value is None:
            logger.warning(f"Field {field_path} not found in alert data")
            return match.group(0)  # Keep original if not found
        
        # Escape the value for OQL
        return utils.escape_oql_value(str(value))
    
    query = re.sub(pattern, replace_single_brace_match, query)
    
    # Handle $field.name format
    pattern = r'\$([a-zA-Z0-9_.]+)'
    
    def replace_dollar_match(match):
        field_path = match.group(1)
        value = utils.get_nested_field(alert_data, field_path)
        if value is None:
            logger.warning(f"Field {field_path} not found in alert data")
            return match.group(0)  # Keep original if not found
        
        # Escape the value for OQL
        return utils.escape_oql_value(str(value))
    
    query = re.sub(pattern, replace_dollar_match, query)
    
    return query


def _parse_time_range(range_str: str, alert_timestamp: Optional[str] = None) -> tuple[str, str]:
    """
    Parse a playbook time range specification into start and end times.
    
    Args:
        range_str: Time range like "+/-3d" or "-1h/+1h"
        alert_timestamp: The timestamp of the alert (ISO format)
        
    Returns:
        Tuple of (start_time, end_time) in Security Onion API format
    """
    if not range_str:
        # Default to +/- 1 hour if no range specified
        range_str = "+/-1h"
    
    # Parse the alert timestamp or use current time
    if alert_timestamp:
        try:
            base_time = datetime.fromisoformat(alert_timestamp.replace('Z', '+00:00'))
        except:
            base_time = datetime.now(timezone.utc)
    else:
        base_time = datetime.now(timezone.utc)
    
    # Handle +/-Xd format (e.g., "+/-3d")
    if range_str.startswith("+/-"):
        duration = range_str[3:]
        start_iso = utils.parse_relative_time(f"-{duration}", base_time)
        end_iso = utils.parse_relative_time(f"+{duration}", base_time)
    # Handle -Xh/+Yh format (e.g., "-1h/+1h")
    elif "/" in range_str:
        parts = range_str.split("/")
        if len(parts) == 2:
            start_iso = utils.parse_relative_time(parts[0], base_time)
            end_iso = utils.parse_relative_time(parts[1], base_time)
        else:
            # Fallback to +/- 1 hour
            start_iso = utils.parse_relative_time("-1h", base_time)
            end_iso = utils.parse_relative_time("+1h", base_time)
    else:
        # Try to parse as a single relative time
        start_iso = utils.parse_relative_time(range_str, base_time)
        end_iso = base_time.isoformat()
    
    # Convert ISO format to Security Onion API format
    start_time = _convert_iso_to_api_format(start_iso)
    end_time = _convert_iso_to_api_format(end_iso)
    
    return start_time, end_time


def _convert_iso_to_api_format(iso_timestamp: str) -> str:
    """
    Convert ISO 8601 timestamp to Security Onion API format.
    
    Args:
        iso_timestamp: ISO 8601 format timestamp (e.g., "2025-06-09T08:00:00+00:00")
        
    Returns:
        Security Onion API format (e.g., "2025/06/09 08:00:00 AM")
    """
    try:
        # Parse the ISO timestamp
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        
        # Convert to the required format
        # Format: YYYY/MM/DD HH:MM:SS AM/PM
        return dt.strftime("%Y/%m/%d %I:%M:%S %p")
    except Exception as e:
        logger.warning(f"Failed to convert timestamp {iso_timestamp}: {e}")
        # Return a relative time as fallback
        return "-1h"


async def execute_playbook_question(
    question: Dict[str, Any],
    alert_data: Dict[str, Any],
    alert_timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Execute a single playbook question by running its query.
    
    Args:
        question: The question dictionary from the playbook
        alert_data: The alert data for variable substitution
        alert_timestamp: The timestamp of the alert
        
    Returns:
        Dictionary with question, context, query results, and answer sources
    """
    result = {
        "question": question.get("question", ""),
        "context": question.get("context", ""),
        "answer_sources": question.get("answer_sources", []),
        "query": question.get("query", ""),
        "results": [],
        "error": None
    }
    
    try:
        # Get the query and substitute variables
        query = question.get("query", "")
        if not query:
            result["error"] = "No query provided for this question"
            return result
        
        # Substitute variables from the alert
        query = _substitute_variables(query, alert_data)
        result["executed_query"] = query
        
        # Parse time range
        range_str = question.get("range", "+/-1h")
        start_time, end_time = _parse_time_range(range_str, alert_timestamp)
        
        # Execute the query
        logger.info(f"Executing playbook query: {query} (range: {start_time} to {end_time})")
        
        # Use the existing event query implementation
        query_results = await event_query_tools.query_events_impl(
            oql_query=query,
            start_time=start_time,
            end_time=end_time,
            limit=100  # Reasonable limit for playbook queries
        )
        
        result["results"] = query_results
        
    except Exception as e:
        logger.error(f"Failed to execute playbook question: {e}")
        result["error"] = str(e)
    
    return result


async def execute_playbook_impl(
    alert_id: str,
    alert_data: Optional[Dict[str, Any]] = None,
    playbook_index: Optional[int] = None
) -> Dict[str, Any]:
    """
    Execute a playbook for a given alert.
    
    Args:
        alert_id: The alert/detection ID
        alert_data: Optional alert data for variable substitution
        playbook_index: Optional index to execute a specific playbook (0-based)
        
    Returns:
        Dictionary containing playbook execution results
    """
    try:
        # Fetch playbooks for the detection
        playbooks = await get_playbooks_for_detection(alert_id)
        
        if not playbooks:
            return {
                "alert_id": alert_id,
                "error": "No playbooks found for this detection",
                "playbooks": []
            }
        
        # If specific playbook requested, validate index
        if playbook_index is not None:
            if playbook_index < 0 or playbook_index >= len(playbooks):
                return {
                    "alert_id": alert_id,
                    "error": f"Invalid playbook index. Found {len(playbooks)} playbooks.",
                    "playbooks": []
                }
            playbooks = [playbooks[playbook_index]]
        
        # If no alert data provided, try to fetch it
        if not alert_data:
            # Query for the alert by ID
            alert_query = f'event.id:"{alert_id}" OR rule.uuid:"{alert_id}"'
            alert_results = await event_query_tools.query_events_impl(
                oql_query=alert_query,
                start_time="-7d",  # Look back 7 days for the alert
                end_time="now",
                limit=1
            )
            
            if alert_results and len(alert_results) > 0:
                alert_data = alert_results[0]
            else:
                logger.warning(f"Could not fetch alert data for ID {alert_id}")
                alert_data = {}
        
        # Extract alert timestamp if available
        alert_timestamp = None
        if alert_data:
            alert_timestamp = alert_data.get("@timestamp") or alert_data.get("timestamp")
        
        # Execute each playbook
        results = {
            "alert_id": alert_id,
            "playbooks": []
        }
        
        for playbook in playbooks:
            playbook_result = {
                "name": playbook.get("name", "Unnamed Playbook"),
                "description": playbook.get("description", ""),
                "questions": []
            }
            
            # Execute each question in the playbook
            questions = playbook.get("questions", [])
            for question in questions:
                question_result = await execute_playbook_question(
                    question, 
                    alert_data,
                    alert_timestamp
                )
                playbook_result["questions"].append(question_result)
            
            results["playbooks"].append(playbook_result)
        
        return results
        
    except Exception as e:
        logger.error(f"Failed to execute playbook: {e}")
        return {
            "alert_id": alert_id,
            "error": str(e),
            "playbooks": []
        }