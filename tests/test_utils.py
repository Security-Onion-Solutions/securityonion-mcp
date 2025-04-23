# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import so_modules.utils as utils

# --- Tests for escape_oql_string ---

def test_escape_oql_string_no_quotes():
    """Test escaping a string with no single quotes."""
    assert utils.escape_oql_string("hello world") == "hello world"

def test_escape_oql_string_with_quotes():
    """Test escaping a string containing single quotes."""
    assert utils.escape_oql_string("it's a test") == "it''s a test"

def test_escape_oql_string_empty():
    """Test escaping an empty string."""
    assert utils.escape_oql_string("") == ""

def test_escape_oql_string_non_string():
    """Test escaping non-string types (should be converted to string)."""
    assert utils.escape_oql_string(123) == "123"
    assert utils.escape_oql_string(None) == "None" # Note: str(None) is 'None'
    assert utils.escape_oql_string(["a", "b'c"]) == "['a', 'b''c']" # str representation of list

# --- Tests for filter_event_payload ---

def test_filter_event_payload_basic():
    """Test basic filtering of a dictionary."""
    payload = {"a": 1, "b": 2, "c": 3}
    allowed = {"a", "c", "d"} # 'd' is not in payload
    expected = {"a": 1, "c": 3}
    assert utils.filter_event_payload(payload, allowed) == expected

def test_filter_event_payload_empty_payload():
    """Test filtering an empty dictionary."""
    payload = {}
    allowed = {"a", "b"}
    expected = {}
    assert utils.filter_event_payload(payload, allowed) == expected

def test_filter_event_payload_empty_allowed():
    """Test filtering with an empty set of allowed fields."""
    payload = {"a": 1, "b": 2}
    allowed = set()
    expected = {}
    assert utils.filter_event_payload(payload, allowed) == expected

def test_filter_event_payload_no_match():
    """Test filtering when no allowed fields match the payload."""
    payload = {"a": 1, "b": 2}
    allowed = {"c", "d"}
    expected = {}
    assert utils.filter_event_payload(payload, allowed) == expected

def test_filter_event_payload_non_dict_input():
    """Test filtering when the payload is not a dictionary."""
    payload = ["a", "b"] # A list, not a dict
    allowed = {"a", "b"}
    expected = {} # Should return empty dict
    assert utils.filter_event_payload(payload, allowed) == expected

# --- Tests for parse_time_range ---

# Use a fixed datetime for predictable results
MOCK_NOW = datetime(2024, 5, 15, 10, 30, 0, tzinfo=timezone.utc)
DATE_FORMAT = "%Y/%m/%d %I:%M:%S %p" # Format used in the function

@patch('so_modules.utils.datetime')
def test_parse_time_range_today(mock_dt):
    """Test parsing 'today' time range."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw) # Allow datetime constructor

    expected_start = MOCK_NOW.replace(hour=0, minute=0, second=0, microsecond=0).strftime(DATE_FORMAT)
    expected_end = MOCK_NOW.strftime(DATE_FORMAT)
    start, end = utils.parse_time_range("today")
    assert start == expected_start
    assert end == expected_end

@patch('so_modules.utils.datetime')
def test_parse_time_range_hours(mock_dt):
    """Test parsing 'Xh' time range."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

    expected_start_dt = MOCK_NOW - timedelta(hours=6)
    expected_start = expected_start_dt.strftime(DATE_FORMAT)
    expected_end = MOCK_NOW.strftime(DATE_FORMAT)

    start, end = utils.parse_time_range("6h")
    assert start == expected_start
    assert end == expected_end

    # Test with negative sign (should be ignored)
    start_neg, end_neg = utils.parse_time_range("-6h")
    assert start_neg == expected_start
    assert end_neg == expected_end

@patch('so_modules.utils.datetime')
def test_parse_time_range_days(mock_dt):
    """Test parsing 'Xd' time range."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

    expected_start_dt = MOCK_NOW - timedelta(days=7)
    expected_start = expected_start_dt.strftime(DATE_FORMAT)
    expected_end = MOCK_NOW.strftime(DATE_FORMAT)

    start, end = utils.parse_time_range("7d")
    assert start == expected_start
    assert end == expected_end

    # Test with negative sign (should be ignored)
    start_neg, end_neg = utils.parse_time_range("-7d")
    assert start_neg == expected_start
    assert end_neg == expected_end


@patch('so_modules.utils.datetime')
def test_parse_time_range_invalid_format(mock_dt):
    """Test invalid format raises ValueError."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

    with pytest.raises(ValueError, match="Invalid time range format: invalid_format"):
        utils.parse_time_range("invalid_format")

def test_parse_time_range_invalid_hours_format():
    """Test invalid hours format raises ValueError."""
    with pytest.raises(ValueError, match="Invalid time range format: 10hours"):
        utils.parse_time_range("10hours")
    with pytest.raises(ValueError, match="Invalid hours format: h"):
        utils.parse_time_range("h")

def test_parse_time_range_invalid_days_format():
    """Test invalid days format raises ValueError."""
    with pytest.raises(ValueError, match="Invalid time range format: 5days"):
        utils.parse_time_range("5days")
    with pytest.raises(ValueError, match="Invalid days format: d"):
        utils.parse_time_range("d")


# --- Tests for parse_datetime_string ---

@patch('so_modules.utils.datetime')
def test_parse_datetime_string_now(mock_dt):
    """Test parsing 'now'."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
    assert utils.parse_datetime_string("now") == MOCK_NOW
    assert utils.parse_datetime_string(" NOW ") == MOCK_NOW # Test stripping/case

@patch('so_modules.utils.datetime')
def test_parse_datetime_string_today(mock_dt):
    """Test parsing 'today'."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
    expected_dt = MOCK_NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    assert utils.parse_datetime_string("today") == expected_dt
    assert utils.parse_datetime_string(" ToDaY ") == expected_dt

@patch('so_modules.utils.datetime')
def test_parse_datetime_string_relative_hours(mock_dt):
    """Test parsing relative hours like '-6h'."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
    expected_dt = MOCK_NOW - timedelta(hours=6)
    assert utils.parse_datetime_string("-6h") == expected_dt
    assert utils.parse_datetime_string(" -6h ") == expected_dt

@patch('so_modules.utils.datetime')
def test_parse_datetime_string_relative_days(mock_dt):
    """Test parsing relative days like '-7d'."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
    expected_dt = MOCK_NOW - timedelta(days=7)
    assert utils.parse_datetime_string("-7d") == expected_dt
    assert utils.parse_datetime_string(" -7d ") == expected_dt

def test_parse_datetime_string_absolute():
    """Test parsing an absolute timestamp string."""
    # Note: The function assumes naive timestamps are local and converts to UTC,
    # or treats them as UTC directly. Let's test the specific format.
    # The function currently treats naive as UTC.
    ts_str = "2024/05/10 02:30:00 PM"
    expected_dt = datetime(2024, 5, 10, 14, 30, 0, tzinfo=timezone.utc) # 2 PM UTC
    parsed_dt = utils.parse_datetime_string(ts_str)
    assert parsed_dt == expected_dt
    assert parsed_dt.tzinfo == timezone.utc

def test_parse_datetime_string_invalid_relative():
    """Test invalid relative formats raise ValueError."""
    with pytest.raises(ValueError, match="Invalid relative hours format: -h"):
        utils.parse_datetime_string("-h")
    with pytest.raises(ValueError, match="Invalid time string format: '-6hours'. Use relative"):
        utils.parse_datetime_string("-6hours")
    with pytest.raises(ValueError, match="Invalid relative days format: -d"):
        utils.parse_datetime_string("-d")
    with pytest.raises(ValueError, match="Invalid time string format: '-7days'. Use relative"):
        utils.parse_datetime_string("-7days")
    # Test case where value after '-' is negative (should not happen with regex but good check)
    with pytest.raises(ValueError, match="Invalid relative hours format: --6h"):
         utils.parse_datetime_string("--6h") # This specific case might fail if int() handles '--' unexpectedly, depends on implementation detail. Let's assume it fails parsing int.
    # Test case where value is not integer
    with pytest.raises(ValueError, match="Invalid relative hours format: -xh"):
         utils.parse_datetime_string("-xh")


def test_parse_datetime_string_invalid_absolute():
    """Test invalid absolute formats raise ValueError."""
    with pytest.raises(ValueError, match="Invalid time string format: '2024-05-10 14:30:00'. Use relative"):
        utils.parse_datetime_string("2024-05-10 14:30:00") # Wrong format
    with pytest.raises(ValueError, match="Invalid time string format: 'invalid date'. Use relative"):
        utils.parse_datetime_string("invalid date")

def test_parse_datetime_string_unsupported_relative():
    """Test unsupported relative formats (like '6h' without '-') raise ValueError."""
    with pytest.raises(ValueError, match="Invalid time string format: '6h'. Use relative"):
        utils.parse_datetime_string("6h") # parse_datetime_string requires leading '-' for relative
    with pytest.raises(ValueError, match="Invalid time string format: '7d'. Use relative"):
        utils.parse_datetime_string("7d")