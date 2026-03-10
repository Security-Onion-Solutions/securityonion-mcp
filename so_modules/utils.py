# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

from datetime import datetime, timedelta, timezone
import re
import typing
import logging

log = logging.getLogger(__name__)


def filter_event_payload(payload: dict, allowed_fields: typing.Set[str]) -> dict:
    """
    Filters a dictionary (event payload) to include only keys present in the allowed_fields set.

    Args:
        payload: The dictionary representing the event payload.
        allowed_fields: A set of strings representing the keys to keep.

    Returns:
        A new dictionary containing only the allowed fields that exist in the payload.
    """
    if not isinstance(payload, dict):
        return {}
    return {field: payload[field] for field in allowed_fields if field in payload}

def parse_datetime_string(time_str: str) -> datetime:
    """
    Parses a single time string into a timezone-aware datetime object (UTC).
    Handles relative times ('-6h', '-7d'), keywords ('now', 'today'),
    and absolute timestamps ('YYYY/MM/DD HH:MM:SS AM/PM').
    """
    now = datetime.now(timezone.utc)
    time_str_lower = time_str.lower().strip()
    absolute_format = "%Y/%m/%d %I:%M:%S %p"

    if time_str_lower == "now":
        return now
    elif time_str_lower == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_str_lower.startswith('-') and time_str_lower.endswith('h'):
        try:
            hours_val = int(time_str_lower[1:-1])
            if hours_val < 0: raise ValueError("Negative value after '-' sign")
            return now - timedelta(hours=hours_val)
        except (ValueError, IndexError):
            raise ValueError(f"Invalid relative hours format: {time_str}")
    elif time_str_lower.startswith('-') and time_str_lower.endswith('m'):
        try:
            minutes_val = int(time_str_lower[1:-1])
            if minutes_val < 0: raise ValueError("Negative value after '-' sign")
            return now - timedelta(minutes=minutes_val)
        except (ValueError, IndexError):
            raise ValueError(f"Invalid relative minutes format: {time_str}")
    elif time_str_lower.startswith('-') and time_str_lower.endswith('d'):
        try:
            days_val = int(time_str_lower[1:-1])
            if days_val < 0: raise ValueError("Negative value after '-' sign")
            return now - timedelta(days=days_val)
        except (ValueError, IndexError):
            raise ValueError(f"Invalid relative days format: {time_str}")
    else:
        # Try parsing as absolute timestamp
        try:
            dt = datetime.strptime(time_str, absolute_format)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            raise ValueError(f"Invalid time string format: '{time_str}'. Use relative ('-6h', '-5m', '-7d'), 'now', 'today', or absolute '{absolute_format}'.")



def escape_oql_value(value: typing.Any) -> str:
    """
    Escapes a value for safe inclusion in an OQL query.
    - If the value is a list, it formats it as an OQL list.
    - If the value is a string, it escapes special characters and quotes if necessary.
    - Otherwise, it converts the value to a string.
    """
    if isinstance(value, str):
        # Escape single quotes for OQL by doubling them up
        escaped_value = value.replace("'", "''")
        return f"'{escaped_value}'"
    elif isinstance(value, list):
        # Recursively escape each item in the list
        return f"[{', '.join(map(escape_oql_value, value))}]"
    else:
        # For numbers and other types, just convert to string
        return str(value)


def get_nested_field(data: typing.Dict[str, typing.Any], field_path: str) -> typing.Any:
    """
    Get a value from a nested dictionary using dot notation.
    
    Args:
        data: The dictionary to search
        field_path: Dot-separated path to the field (e.g., "source.ip")
        
    Returns:
        The value at the field path, or None if not found
    """
    if not data or not field_path:
        return None
    
    parts = field_path.split('.')
    current = data
    
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    
    return current


def build_api_time_range(start_time: typing.Optional[str], end_time: typing.Optional[str]) -> typing.Optional[str]:
    """
    Build a time range string for the API from start and end times.
    
    Args:
        start_time: Optional start time string
        end_time: Optional end time string
        
    Returns:
        Formatted time range string or None if no valid range could be created
    """
    if not start_time and not end_time:
        log.info("No time range provided, using API default.")
        return None
        
    api_date_format = "%Y/%m/%d %I:%M:%S %p"
    
    try:
        start_dt = parse_datetime_string(start_time) if start_time else None
        end_dt = parse_datetime_string(end_time) if end_time else None
        
        # Both start and end times provided
        if start_dt and end_dt:
            if start_dt >= end_dt:
                log.warning(f"Start time '{start_time}' is not before end time '{end_time}'. Swapping them.")
                start_dt, end_dt = end_dt, start_dt
            return f"{start_dt.strftime(api_date_format)} - {end_dt.strftime(api_date_format)}"
            
        # Only start time provided
        elif start_dt:
            now_dt = parse_datetime_string("now")
            if start_dt >= now_dt:
                log.warning(f"Start time '{start_time}' is in the future or now. Query might return no results.")
            return f"{start_dt.strftime(api_date_format)} - {now_dt.strftime(api_date_format)}"
            
        # Only end time provided
        elif end_dt:
            log.warning("Only end_time provided. Relying on API default start time.")
            return None
        
        
    except ValueError as e:
        log.error(f"Error parsing time strings: {e}", exc_info=True)
        raise ValueError(f"Invalid time format: {e}")
        
    return None  # pragma: no cover


def validate_configuration():
    """
    Checks if the required configuration is set.
    Raises ValueError if configuration is missing.
    """
    from . import config
    try:
        config.check_config()
        if config.SO_CA_CERT:
            log.info(f"Using custom CA certificate from: {config.SO_CA_CERT}")
        else:
            log.info("Using default SSL verification.")
    except ValueError as e:
        log.critical(f"Configuration error: {e}")
        raise