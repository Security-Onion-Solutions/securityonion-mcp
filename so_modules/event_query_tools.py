# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Module for event query tools.
"""
import re
import logging
import typing
import datetime
from . import api
from . import utils
from . import config

log = logging.getLogger(__name__)

async def query_events_impl(
    oql_query: str,
    start_time: typing.Optional[str] = None,
    end_time: typing.Optional[str] = None,
    limit: int = 100,
    groupby_field: typing.Optional[str] = None
) -> list[dict]:
    """
    Implementation for a generic event query tool. Executes an OQL query against events.
    Supports optional grouping via the groupby_field parameter.
    
    Args:
        oql_query: The OQL query string to execute
        start_time: Optional start time for the query range (e.g., "-1h", "2023-10-26 10:00:00")
        end_time: Optional end time for the query range (e.g., "now", "2023-10-26 12:00:00")
        limit: The maximum number of events to return (default: 100)
        groupby_field: Optional OQL field name to group results by
        
    Returns:
        A list of event dictionaries matching the query with filtered payloads
    """
    # --- Input Validation ---
    # Validate groupby_field
    if groupby_field:
        if not re.match(r"^[\w.-]+$", groupby_field):
            log.error(f"Invalid characters detected in groupby_field: {groupby_field}")
            raise ValueError(f"Invalid characters in groupby_field. Only unicode letters, numbers, underscore, period, and hyphen are allowed.")

    # Basic validation for oql_query (balanced quotes)
    if oql_query.count("'") % 2 != 0 or oql_query.count('"') % 2 != 0:
        log.error(f"Unbalanced quotes detected in oql_query: {oql_query}")
        raise ValueError("Unbalanced quotes in oql_query.")
    # --- End Input Validation ---

    # Ensure all 'and' operators are uppercase
    oql_query = _capitalize_standalone_and(oql_query)
    
    # Initialize parameters dictionary
    params = {"eventLimit": str(limit)}
    
    try:
        # Prepare and enhance the query
        final_oql = _enhance_query(oql_query)
        
        # Add groupby if provided
        if groupby_field:
            final_oql += f" | groupby {groupby_field}"
            log.info(f"Applying groupby clause for field: {groupby_field}")
        
        params["query"] = final_oql
        log.info(f"Executing event query: {final_oql}")
        
        # Handle time range
        time_range = utils.build_api_time_range(start_time, end_time)
        if time_range:
            params["range"] = time_range
            log.info(f"Using time range: {time_range}")
        
        # Make API request
        log.info(f"API Params: {params}")
        data = await api.make_so_api_request("/connect/events", params)
        
        # Process response
        if groupby_field:
            return _process_groupby_response(data, groupby_field)
        else:
            return _process_events_response(data)
            
    except ValueError as ve:
        log.error(f"Value error in query_events_impl: {ve}", exc_info=True)
        return [{"error": f"Invalid input: {str(ve)}"}]
    except Exception as e:
        error_details = {
            "type": type(e).__name__,
            "message": str(e),
            "oql_query": oql_query,
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit,
            "groupby_field": groupby_field
        }
        log.error(f"API request failed for event query: {error_details}", exc_info=True)
        return [{"error": "An internal error occurred while processing the event query."}]


def _process_groupby_response(data: dict, groupby_field: str) -> list[dict]:
    """
    Process API response for groupby queries.
    
    Args:
        data: The API response data
        groupby_field: The field used for grouping
        
    Returns:
        Processed groupby results
    """
    if "metrics" not in data:
        log.warning(f"Groupby field '{groupby_field}' was provided, but no 'metrics' key found in the API response.")
        return []
        
    log.info("Processing metrics response due to groupby.")
    metrics = data.get("metrics", {})
    
    # Find the groupby key in metrics
    groupby_key = next((key for key in metrics.keys() if key.startswith("groupby_")), None)
    
    if groupby_key:
        return metrics.get(groupby_key, [])
    else:
        log.warning("Groupby was used, 'metrics' key found, but no 'groupby_*' key. Returning full metrics dict.")
        return [metrics]


def _enhance_query(oql_query: str) -> str:
    """
    Enhance the OQL query with additional filters and transformations.
    
    Args:
        oql_query: The original OQL query
        
    Returns:
        Enhanced OQL query
    """
    # Add metadata filter to exclude logs-soc-so index
    if "NOT metadata.raw_index:" not in oql_query:
        oql_query = f"{oql_query} AND NOT metadata.raw_index:\"logs-soc-so\""
    
    return oql_query


def _process_events_response(data: dict) -> list[dict]:
    """
    Process API response for standard event queries.
    
    Args:
        data: The API response data
        
    Returns:
        Processed event results with filtered payloads
    """
    log.info("Processing standard events list from response.")
    events = data.get("events", [])
    processed_payloads = []
    
    try:
        for event in events:
            payload = event.get('payload', {})
            # Filter payload to include only default fields
            filtered_payload = utils.filter_event_payload(payload, config.DEFAULT_FIELDS)
            processed_payloads.append({"payload": filtered_payload})
        return processed_payloads
    except Exception as e:
        log.error(f"Unexpected error during payload processing: {e}", exc_info=True)
        raise


def _capitalize_standalone_and(query: str) -> str:
    """
    Capitalizes 'and' when it's a standalone word, ignoring 'and' inside quotes.
    """
    # Split the query by quoted strings, keeping the delimiters
    parts = re.split(r'(".*?"|\'.*?\')', query)
    
    # Process each part: capitalize 'and' in non-quoted parts
    for i in range(len(parts)):
        # Non-quoted parts are at even indices
        if i % 2 == 0:
            parts[i] = re.sub(r'\band\b', 'AND', parts[i], flags=re.IGNORECASE)
            
    return "".join(parts)
