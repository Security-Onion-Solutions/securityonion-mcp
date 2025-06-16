# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
import pytest_asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta, timezone

# Modules to test
from so_modules import event_query_tools
from so_modules import config

# --- Fixtures ---

@pytest.fixture
def mock_api(mocker):
    """Fixture to mock the api.make_so_api_request function."""
    mock = mocker.patch('so_modules.api.make_so_api_request', new_callable=AsyncMock)
    # Default successful response
    mock.return_value = {"events": [{"payload": {"field1": "value1", "_id": "event1"}}], "metrics": {}}
    return mock

@pytest.fixture
def mock_utils(mocker):
    """Fixture to mock utility functions."""
    mocks = {
        'parse_datetime_string': mocker.patch('so_modules.utils.parse_datetime_string'),
        'filter_event_payload': mocker.patch('so_modules.utils.filter_event_payload',
                                            side_effect=lambda payload, fields: {k: payload[k] for k in fields if k in payload})
    }
    # Mock the config fields used by filter_event_payload
    mocker.patch('so_modules.config.DEFAULT_FIELDS', ['field1', 'source.ip', 'destination.ip'])
    return mocks

# --- Additional Test Cases for Coverage ---

@pytest.mark.asyncio
async def test_query_events_impl_invalid_groupby_field(mock_api, mock_utils):
    """Test query_events_impl with invalid groupby_field characters."""
    with pytest.raises(ValueError, match="Invalid characters in groupby_field"):
        await event_query_tools.query_events_impl(oql_query='source.ip:"1.1.1.1"', groupby_field="invalid;field")

@pytest.mark.asyncio
async def test_query_events_impl_unbalanced_quotes(mock_api, mock_utils):
    """Test query_events_impl with unbalanced quotes in the query."""
    with pytest.raises(ValueError, match="Unbalanced quotes in oql_query"):
        await event_query_tools.query_events_impl(oql_query='source.ip:"1.1.1.1')
    
    with pytest.raises(ValueError, match="Unbalanced quotes in oql_query"):
        await event_query_tools.query_events_impl(oql_query="source.ip:'1.1.1.1")

@pytest.mark.asyncio
async def test_query_events_impl_value_error(mock_api, mock_utils):
    """Test query_events_impl handling ValueError."""
    # Mock parse_datetime_string to raise ValueError
    mock_utils['parse_datetime_string'].side_effect = ValueError("Invalid time format")
    
    result = await event_query_tools.query_events_impl(
        oql_query='source.ip:"1.1.1.1"',
        start_time="invalid_time"
    )
    
    assert result[0]["error"].startswith("Invalid input: Invalid time format")
    mock_api.assert_not_called()


@pytest.mark.asyncio
async def test_process_groupby_response_no_metrics():
    """Test _process_groupby_response when no metrics key is present."""
    data = {"events": []}  # No metrics key
    result = event_query_tools._process_groupby_response(data, "source.ip")
    assert result == []

@pytest.mark.asyncio
async def test_process_groupby_response_no_groupby_key():
    """Test _process_groupby_response when no groupby_* key is found."""
    data = {"metrics": {"other_key": "value"}}  # No groupby_* key
    result = event_query_tools._process_groupby_response(data, "source.ip")
    assert result == [{"other_key": "value"}]

@pytest.mark.asyncio
async def test_process_events_response_error_handling():
    """Test _process_events_response error handling."""
    with patch('so_modules.utils.filter_event_payload') as mock_filter:
        mock_filter.side_effect = Exception("Unexpected error")
        
        data = {"events": [{"payload": {"field1": "value1"}}]}
        
        with pytest.raises(Exception, match="Unexpected error"):
            event_query_tools._process_events_response(data)

@pytest.mark.asyncio
async def test_query_events_impl_only_end_time(mock_api, mock_utils):
    """Test query_events_impl with only end_time provided."""
    # Setup mock for parse_datetime_string
    end_dt_mock = MagicMock(name="end_dt")
    end_dt_mock.strftime.return_value = "2025/04/03 11:00:00 AM"
    mock_utils['parse_datetime_string'].return_value = end_dt_mock
    
    await event_query_tools.query_events_impl(
        oql_query='rule.name:"Test"',
        end_time="2025-04-03 11:00"
    )
    
    # Verify that range parameter is not set when only end_time is provided
    mock_api.assert_called_once()
    call_args, call_kwargs = mock_api.call_args
    params = call_args[1]
    assert "range" not in params



@pytest.mark.asyncio
async def test_query_events_impl_and_in_quotes(mock_api, mock_utils):
    """Test that 'and' inside a quoted string is not capitalized."""
    oql_query = 'field1:"Mike and Amanda" and field2:true'
    expected_query = 'field1:"Mike and Amanda" AND field2:true AND NOT metadata.raw_index:"logs-soc-so"'

    await event_query_tools.query_events_impl(oql_query=oql_query)

    mock_api.assert_called_once()
    # The second argument to make_so_api_request is the params dict
    called_params = mock_api.call_args[0][1]
    assert called_params['query'] == expected_query