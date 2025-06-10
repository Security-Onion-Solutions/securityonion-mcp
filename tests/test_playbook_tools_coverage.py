# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""Additional tests for playbook_tools to ensure 100% coverage."""

import pytest
from unittest.mock import patch, AsyncMock
from datetime import datetime, timezone
from so_modules import playbook_tools


class TestPlaybookToolsCoverage:
    """Additional test cases for complete coverage of playbook_tools module."""
    
    @pytest.mark.asyncio
    async def test_get_playbooks_empty_response(self):
        """Test handling of empty response from API."""
        with patch('so_modules.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            # Return non-list response
            mock_api.return_value = {"error": "not found"}
            
            result = await playbook_tools.get_playbooks_for_detection("test-id")
            
            # Should return empty list for non-list responses
            assert result == []
    
    def test_parse_time_range_invalid_split_format(self):
        """Test handling of invalid split format time ranges."""
        # More than 2 parts in split format
        start, end = playbook_tools._parse_time_range("-1h/+1h/extra", None)
        
        # Should fallback to +/- 1 hour in API format
        assert "/" in start
        assert "/" in end
        assert ("AM" in start or "PM" in start)
        assert ("AM" in end or "PM" in end)
    
    def test_parse_time_range_single_relative(self):
        """Test parsing single relative time (not split format)."""
        base_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        alert_timestamp = base_time.isoformat()
        
        start, end = playbook_tools._parse_time_range("-3h", alert_timestamp)
        
        # Start should be 3 hours before base_time in API format
        assert start == "2024/01/15 09:00:00 AM"
        # End should be the base_time in API format
        assert end == "2024/01/15 12:00:00 PM"
    
    def test_parse_time_range_invalid_alert_timestamp(self):
        """Test handling of invalid alert timestamp."""
        # Invalid timestamp format should fallback to current time
        start, end = playbook_tools._parse_time_range("+/-1h", "invalid-timestamp")
        
        # Should still return valid API format times
        assert "/" in start
        assert "/" in end
        assert ("AM" in start or "PM" in start)
        assert ("AM" in end or "PM" in end)
    
    @pytest.mark.asyncio
    async def test_execute_playbook_impl_no_alert_timestamp(self):
        """Test playbook execution when alert has no timestamp field."""
        alert_id = "test-alert"
        alert_data_no_timestamp = {
            "source": {"ip": "10.0.0.1"},
            "event": {"id": alert_id}
            # No @timestamp or timestamp field
        }
        
        mock_playbooks = [
            {
                "name": "Test Playbook",
                "questions": [
                    {
                        "question": "Test Q",
                        "query": "source.ip:{{source.ip}}",
                        "range": "+/-1h"
                    }
                ]
            }
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_pb:
            with patch('so_modules.event_query_tools.query_events_impl', new_callable=AsyncMock) as mock_query:
                mock_get_pb.return_value = mock_playbooks
                mock_query.return_value = []
                
                # Pass alert_data to avoid the fetch
                result = await playbook_tools.execute_playbook_impl(
                    alert_id, 
                    alert_data=alert_data_no_timestamp
                )
                
                # Should still execute successfully
                assert result["alert_id"] == alert_id
                assert len(result["playbooks"]) == 1
    
    @pytest.mark.asyncio 
    async def test_execute_playbook_impl_alert_with_timestamp_field(self):
        """Test using 'timestamp' field when '@timestamp' is not available."""
        alert_id = "test-alert"
        alert_data = {
            "timestamp": "2024-01-15T12:00:00Z",  # Using 'timestamp' instead of '@timestamp'
            "source": {"ip": "10.0.0.1"}
        }
        
        mock_playbooks = [
            {
                "name": "Test Playbook",
                "questions": [
                    {
                        "question": "Test",
                        "query": "test",
                        "range": "+/-1h"
                    }
                ]
            }
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_pb:
            with patch('so_modules.playbook_tools.execute_playbook_question', new_callable=AsyncMock) as mock_exec_q:
                mock_get_pb.return_value = mock_playbooks
                mock_exec_q.return_value = {"results": [], "error": None}
                
                result = await playbook_tools.execute_playbook_impl(
                    alert_id,
                    alert_data=alert_data
                )
                
                # Verify the timestamp was passed to execute_playbook_question
                mock_exec_q.assert_called_once()
                call_args = mock_exec_q.call_args[0]
                assert call_args[2] == "2024-01-15T12:00:00Z"  # alert_timestamp parameter
    
    def test_substitute_variables_dollar_missing_field(self):
        """Test dollar sign variable substitution with missing field."""
        query = "field:$missing.field"
        alert_data = {"other": "value"}
        
        # Should keep original when field is missing
        result = playbook_tools._substitute_variables(query, alert_data)
        assert result == "field:$missing.field"