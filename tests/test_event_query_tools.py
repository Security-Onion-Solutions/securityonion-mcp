# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
import pytest_asyncio
from unittest.mock import MagicMock, AsyncMock # Import AsyncMock

# Modules to test
from so_modules import event_query_tools
from so_modules import config # Needed for mocking DEFAULT_FIELDS

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
        'parse_time_range': mocker.patch('so_modules.utils.parse_time_range', return_value=("2025/04/04 00:00:00 AM", "2025/04/04 11:59:59 PM")),
        'parse_datetime_string': mocker.patch('so_modules.utils.parse_datetime_string'), # Configure per test if needed
        'escape_oql_string': mocker.patch('so_modules.utils.escape_oql_string', side_effect=lambda x: x.replace('"', '\\"')), # Simple escape mock
        'filter_event_payload': mocker.patch('so_modules.utils.filter_event_payload', side_effect=lambda payload, fields: {k: payload[k] for k in fields if k in payload}) # Basic filter mock
    }
    # Mock the config fields used by filter_event_payload
    mocker.patch('so_modules.config.DEFAULT_FIELDS', ['field1', 'network.community_id', 'log.id.uid', 'rule.name', 'source.ip', 'destination.ip', 'dns.query.name'])
    return mocks


# --- Test Cases ---

@pytest.mark.asyncio
async def test_query_events_impl_basic(mock_api, mock_utils):
    """Test query_events_impl with a basic OQL query."""
    mock_api.return_value = {
        "events": [
            {
                "payload": {
                    "source.ip": "1.1.1.1",
                    "_id": "evt1",
                    "field1": "value1",
                    "network.community_id": "comm1"
                }
            }
        ],
        "total": 1
    }
    result = await event_query_tools.query_events_impl(oql_query='source.ip:"1.1.1.1"')

    mock_api.assert_called_once()
    call_args, call_kwargs = mock_api.call_args
    params = call_args[1]
    # Check that the query contains the expected parts
    assert 'source.ip:"1.1.1.1"' in params["query"]
    assert 'NOT metadata.raw_index:"logs-soc-so"' in params["query"]
    assert params["eventLimit"] == "100"  # Default limit
    assert result == [
        {
            "payload": {
                "source.ip": "1.1.1.1",
                "field1": "value1",
                "network.community_id": "comm1"
            }
        }
    ] # Expect filtered payload

    # Verify filter_event_payload was called correctly
    mock_utils['filter_event_payload'].assert_called_once()
    call_args, call_kwargs = mock_utils['filter_event_payload'].call_args
    # Check that the payload contains all expected fields
    assert call_args[0]["source.ip"] == "1.1.1.1"
    assert call_args[0]["_id"] == "evt1"
    assert call_args[0]["field1"] == "value1"
    assert call_args[1] == ['field1', 'network.community_id', 'log.id.uid', 'rule.name', 'source.ip', 'destination.ip', 'dns.query.name']
@pytest.mark.asyncio
async def test_query_events_impl_with_metadata_filtering(mock_api, mock_utils):
    """Test that query_events_impl adds metadata filtering."""
    mock_api.return_value = {
        "events": [
            {
                "payload": {
                    "source.ip": "1.1.1.1",
                    "_id": "evt1",
                    "field1": "value1",
                    "network.community_id": "comm1"
                }
            }
        ],
        "total": 1
    }
    # Execute a basic query
    await event_query_tools.query_events_impl(oql_query='event.dataset:"zeek.conn" AND source.ip:"1.1.1.1"')
    # Verify the query sent to API includes the metadata filtering
    mock_api.assert_called_once()
    call_args, call_kwargs = mock_api.call_args
    params = call_args[1]
    query_param = params.get("query", "")
    # It should contain the metadata filter
    assert 'NOT metadata.raw_index:"logs-soc-so"' in query_param
    # And still contain the original query parts
    assert 'event.dataset:"zeek.conn"' in query_param
    assert 'source.ip:"1.1.1.1"' in query_param


@pytest.mark.asyncio
async def test_query_events_impl_with_time(mock_api, mock_utils):
    """Test query_events_impl with start and end times."""
    # Mock specific datetime parsing for this test
    start_dt_mock = MagicMock(name="start_dt")
    start_dt_mock.strftime.return_value = "2025/04/03 10:00:00 AM"
    end_dt_mock = MagicMock(name="end_dt")
    end_dt_mock.strftime.return_value = "2025/04/03 11:00:00 AM"
    # Configure comparison behavior for the TypeError fix (accept self, other)
    start_dt_mock.__ge__ = lambda self, other: False # start_dt >= end_dt -> False
    end_dt_mock.__ge__ = lambda self, other: True # end_dt >= start_dt -> True
    mock_utils['parse_datetime_string'].side_effect = [start_dt_mock, end_dt_mock]

    await event_query_tools.query_events_impl(oql_query='rule.name:"Test"', start_time="2025-04-03 10:00", end_time="2025-04-03 11:00")

    mock_api.assert_called_once()
    call_args, call_kwargs = mock_api.call_args
    params = call_args[1]
    # Check that the query contains the expected parts
    assert 'rule.name:"Test"' in params["query"]
    assert 'NOT metadata.raw_index:"logs-soc-so"' in params["query"]
    assert params["range"] == "2025/04/03 10:00:00 AM - 2025/04/03 11:00:00 AM"
    assert params["eventLimit"] == "100"
    assert mock_utils['parse_datetime_string'].call_count == 2

@pytest.mark.asyncio
async def test_query_events_impl_groupby(mock_api, mock_utils):
    """Test query_events_impl with groupby_field."""
    mock_api.return_value = {"metrics": {"groupby_source.ip": [{"key": "1.1.1.1", "doc_count": 10}]}}
    result = await event_query_tools.query_events_impl(oql_query='tags:alert', groupby_field="source.ip")

    mock_api.assert_called_once()
    # Don't check the exact query string as it may change with implementation details
    # Just verify that the groupby clause is added
    call_args, call_kwargs = mock_api.call_args
    assert "| groupby source.ip" in call_args[1]["query"]
    assert call_args[1]["eventLimit"] == "100"
    assert result == [{"key": "1.1.1.1", "doc_count": 10}] # Expect metrics result
    # Ensure filter_event_payload was NOT called for groupby
    mock_utils['filter_event_payload'].assert_not_called()

@pytest.mark.asyncio
async def test_error_handling(mock_api, mock_utils):
    """Test generic error handling returns an error dict."""
    # Test error handling for query_events_impl
    mock_api.side_effect = Exception("API Failure")
    result = await event_query_tools.query_events_impl("oql")
    assert result == [{"error": "An internal error occurred while processing the event query."}]

