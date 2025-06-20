# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import json
from so_modules import alert_tools, config


@pytest.mark.asyncio
async def test_acknowledge_alerts_success():
    """Test successful alert acknowledgment."""
    # Mock the token retrieval
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.return_value = "test_token"
        
        # Mock the requests.post call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "updated": 5,
            "failed": 0,
            "errors": [],
            "completeTime": "2024-12-04T19:54:33.822293482Z",
            "elapsedMs": 299
        }
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            
            # Call the function
            result = await alert_tools.acknowledge_alerts_impl(
                acknowledge=True,
                search_filter="tags:alert AND NOT event.acknowledged:true"
            )
            
            # Verify the result
            assert result["updated"] == 5
            assert result["failed"] == 0
            assert len(result["errors"]) == 0
            
            # Verify the API call was made correctly
            call_args = mock_thread.call_args
            assert call_args[0][0].__name__ == 'post'
            # Check the URL
            url_arg = call_args[0][1]
            assert url_arg.endswith("/connect/events/ack")
            # Check headers
            headers_arg = call_args[1]['headers']
            assert headers_arg["Authorization"] == "Bearer test_token"
            assert headers_arg["Content-Type"] == "application/json"
            # Check body
            body_arg = call_args[1]['json']
            assert body_arg["acknowledge"] is True
            assert body_arg["searchFilter"] == "tags:alert AND NOT event.acknowledged:true"
            assert body_arg["timezone"] == "America/New_York"
            assert body_arg["dateRangeFormat"] == "2006/01/02 3:04:05 PM"


@pytest.mark.asyncio
async def test_acknowledge_alerts_with_all_parameters():
    """Test alert acknowledgment with all optional parameters."""
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.return_value = "test_token"
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "updated": 3,
            "failed": 0,
            "errors": [],
            "completeTime": "2024-12-04T19:54:33.822293482Z",
            "elapsedMs": 150
        }
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            
            # Call with all parameters
            result = await alert_tools.acknowledge_alerts_impl(
                acknowledge=False,  # Unacknowledge
                search_filter="tags:alert AND event.acknowledged:true",
                event_filter={"rule.name": "Test Rule", "event.module": "sigma"},
                date_range="2024/12/01 00:00:00 AM - 2024/12/04 11:59:59 PM",
                date_range_format="2006/01/02 3:04:05 PM",
                timezone="UTC",
                escalate=False
            )
            
            # Verify the result
            assert result["updated"] == 3
            
            # Check the request body
            call_args = mock_thread.call_args
            body_arg = call_args[1]['json']
            assert body_arg["acknowledge"] is False
            assert body_arg["searchFilter"] == "tags:alert AND event.acknowledged:true"
            assert body_arg["eventFilter"] == {"rule.name": "Test Rule", "event.module": "sigma"}
            assert body_arg["dateRange"] == "2024/12/01 00:00:00 AM - 2024/12/04 11:59:59 PM"
            assert body_arg["dateRangeFormat"] == "2006/01/02 3:04:05 PM"
            assert body_arg["timezone"] == "UTC"
            assert body_arg["escalate"] is False


@pytest.mark.asyncio
async def test_acknowledge_alerts_bad_request():
    """Test handling of 400 bad request error."""
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.return_value = "test_token"
        
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Invalid search filter syntax"
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            
            result = await alert_tools.acknowledge_alerts_impl(
                acknowledge=True,
                search_filter="invalid syntax here"
            )
            
            assert result["error"] == "Invalid input parameters"
            assert "Invalid search filter syntax" in result["details"]


@pytest.mark.asyncio
async def test_acknowledge_alerts_authentication_error():
    """Test handling of 401 authentication error."""
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.return_value = "test_token"
        
        mock_response = MagicMock()
        mock_response.status_code = 401
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            
            result = await alert_tools.acknowledge_alerts_impl(
                acknowledge=True,
                search_filter="tags:alert"
            )
            
            assert result["error"] == "Authentication failed"
            assert "not properly authenticated" in result["details"]


@pytest.mark.asyncio
async def test_acknowledge_alerts_server_error():
    """Test handling of 500 server error."""
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.return_value = "test_token"
        
        mock_response = MagicMock()
        mock_response.status_code = 500
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            
            result = await alert_tools.acknowledge_alerts_impl(
                acknowledge=True,
                search_filter="tags:alert"
            )
            
            assert result["error"] == "Internal server error"
            assert "SOC logs" in result["details"]


@pytest.mark.asyncio
async def test_acknowledge_alerts_token_failure():
    """Test handling of token retrieval failure."""
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.side_effect = Exception("Failed to get token")
        
        result = await alert_tools.acknowledge_alerts_impl(
            acknowledge=True,
            search_filter="tags:alert"
        )
        
        assert result["error"] == "Unexpected error"
        assert "Failed to get token" in result["details"]


@pytest.mark.asyncio
async def test_acknowledge_alerts_json_parse_error():
    """Test handling of JSON parse error in response."""
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.return_value = "test_token"
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            
            result = await alert_tools.acknowledge_alerts_impl(
                acknowledge=True,
                search_filter="tags:alert"
            )
            
            assert result["error"] == "Invalid response format"
            assert "Invalid JSON" in result["details"]


@pytest.mark.asyncio
async def test_acknowledge_alerts_minimal_parameters():
    """Test alert acknowledgment with minimal parameters."""
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.return_value = "test_token"
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "updated": 10,
            "failed": 2,
            "errors": ["Error 1", "Error 2"],
            "completeTime": "2024-12-04T19:54:33.822293482Z",
            "elapsedMs": 500
        }
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            
            # Call with only acknowledge parameter (minimal)
            result = await alert_tools.acknowledge_alerts_impl(acknowledge=True)
            
            # Verify the result
            assert result["updated"] == 10
            assert result["failed"] == 2
            assert len(result["errors"]) == 2
            
            # Check the request body has defaults
            call_args = mock_thread.call_args
            body_arg = call_args[1]['json']
            assert body_arg["acknowledge"] is True
            assert body_arg["timezone"] == "America/New_York"
            assert body_arg["dateRangeFormat"] == "2006/01/02 3:04:05 PM"
            # Should not have optional fields
            assert "searchFilter" not in body_arg
            assert "eventFilter" not in body_arg
            assert "dateRange" not in body_arg
            assert "escalate" not in body_arg


@pytest.mark.asyncio
async def test_acknowledge_alerts_request_exception():
    """Test handling of request exception during API call."""
    import requests
    
    with patch('so_modules.api.get_so_token', new_callable=AsyncMock) as mock_get_token:
        mock_get_token.return_value = "test_token"
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            # Simulate a connection error
            mock_thread.side_effect = requests.exceptions.ConnectionError("Connection refused")
            
            result = await alert_tools.acknowledge_alerts_impl(
                acknowledge=True,
                search_filter="tags:alert"
            )
            
            assert result["error"] == "Request failed"
            assert "Connection refused" in result["details"]