# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

from datetime import datetime, timedelta, timezone
import re
import typing

def escape_oql_string(value: typing.Any) -> str:
    """
    Escapes a value for safe inclusion within an OQL string literal.
    Converts the value to a string and replaces single quotes (') with
    two single quotes ('').

    Args:
        value: The value to escape.

    Returns:
        The escaped string, safe for OQL string literals.
    """
    if isinstance(value, list):
        return "[" + ", ".join([f"'{escape_oql_string(item)}'" for item in value]) + "]"
    return str(value).replace("'", "''")

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

def parse_time_range(time_range_str: str) -> tuple[str, str]:
    """
    Parses a time range string (e.g., '24h', '7d', 'today') into start and end datetime strings
    formatted for the Security Onion API.
    """
    now = datetime.now(timezone.utc)
    start_time = None

    time_range_str = time_range_str.lower().strip()

    if time_range_str == "today":
        start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_range_str.endswith('h'):
        try:
            match = re.match(r"^(-?)(\d+)h$", time_range_str)
            if match:
                hours_val = int(match.group(2))
                start_time = now - timedelta(hours=hours_val)
            else:
                raise ValueError(f"Invalid hours format: {time_range_str}")
        except (ValueError, IndexError):
            raise ValueError(f"Invalid hours format: {time_range_str}")
    elif time_range_str.endswith('d'):
        try:
            match = re.match(r"^(-?)(\d+)d$", time_range_str)
            if match:
                days_val = int(match.group(2))
                start_time = now - timedelta(days=days_val)
            else:
                raise ValueError(f"Invalid days format: {time_range_str}")
        except (ValueError, IndexError):
            raise ValueError(f"Invalid days format: {time_range_str}")
    else:
        raise ValueError(f"Invalid time range format: {time_range_str}")

    date_format = "%Y/%m/%d %I:%M:%S %p"
    start_str = start_time.strftime(date_format)
    end_str = now.strftime(date_format)

    return start_str, end_str

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