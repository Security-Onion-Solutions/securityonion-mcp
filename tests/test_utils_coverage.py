# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import so_modules.utils as utils

# --- Additional Tests for escape_oql_string ---

def test_escape_oql_string_list():
    """Test escaping a list of values."""
    # Test with a simple list
    assert utils.escape_oql_string(["a", "b"]) == "['a', 'b']"
    
    # Test with a list containing quotes
    assert utils.escape_oql_string(["a", "b's", "c"]) == "['a', 'b''s', 'c']"
    
    # Test with an empty list
    assert utils.escape_oql_string([]) == "[]"
    
    # Test with a nested list
    nested_list = ["a", ["b", "c"]]
    # The inner list will be converted to string first
    expected = "['a', '['b', 'c']']"
    assert utils.escape_oql_string(nested_list) == expected

# --- Additional Tests for parse_datetime_string ---

# Use a fixed datetime for predictable results
MOCK_NOW = datetime(2024, 5, 15, 10, 30, 0, tzinfo=timezone.utc)

@patch('so_modules.utils.datetime')
def test_parse_datetime_string_relative_minutes(mock_dt):
    """Test parsing relative minutes like '-30m'."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
    
    # Test with minutes
    expected_dt = MOCK_NOW - timedelta(minutes=30)
    assert utils.parse_datetime_string("-30m") == expected_dt
    assert utils.parse_datetime_string(" -30m ") == expected_dt
    
    # Test with invalid minutes format
    with pytest.raises(ValueError, match="Invalid relative minutes format"):
        utils.parse_datetime_string("-m")

# Add a separate test for invalid time string format
@patch('so_modules.utils.datetime')
def test_parse_datetime_string_invalid_format(mock_dt):
    """Test parsing invalid time string format."""
    mock_dt.now.return_value = MOCK_NOW
    mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
    
    # Mock datetime.strptime to raise ValueError
    mock_dt.strptime.side_effect = ValueError("Invalid time string format")
    
    with pytest.raises(ValueError):
        utils.parse_datetime_string("not_a_valid_time")
    
    # Test with negative value after '-' sign
    with pytest.raises(ValueError, match="Invalid relative minutes format"):
        utils.parse_datetime_string("--30m")
    
    # Test with non-integer value
    with pytest.raises(ValueError, match="Invalid relative minutes format"):
        utils.parse_datetime_string("-xm")