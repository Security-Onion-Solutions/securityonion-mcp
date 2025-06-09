# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone
from so_modules import playbook_tools


class TestPlaybookTools:
    """Test cases for playbook_tools module."""
    
    @pytest.mark.asyncio
    async def test_get_playbooks_for_detection_success(self):
        """Test successful retrieval of playbooks for a detection."""
        mock_playbooks = [
            {
                "name": "Test Playbook",
                "description": "A test playbook",
                "questions": [
                    {
                        "question": "What is the source IP?",
                        "query": "source.ip:{{source.ip}}",
                        "context": "Identifying the source",
                        "range": "+/-1h"
                    }
                ]
            }
        ]
        
        with patch('so_modules.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_playbooks
            
            result = await playbook_tools.get_playbooks_for_detection("test-detection-id")
            
            assert result == mock_playbooks
            mock_api.assert_called_once_with("/connect/playbook/detection/test-detection-id", method="GET")
    
    @pytest.mark.asyncio
    async def test_get_playbooks_for_detection_failure(self):
        """Test handling of API failure when retrieving playbooks."""
        with patch('so_modules.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.side_effect = Exception("API Error")
            
            with pytest.raises(Exception) as exc_info:
                await playbook_tools.get_playbooks_for_detection("test-detection-id")
            
            assert str(exc_info.value) == "API Error"
    
    def test_substitute_variables_double_braces(self):
        """Test variable substitution with {{field}} format."""
        query = "source.ip:{{source.ip}} AND destination.ip:{{destination.ip}}"
        alert_data = {
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "192.168.1.1"}
        }
        
        result = playbook_tools._substitute_variables(query, alert_data)
        
        assert result == "source.ip:10.0.0.1 AND destination.ip:192.168.1.1"
    
    def test_substitute_variables_dollar_sign(self):
        """Test variable substitution with $field format."""
        query = "user.name:$user.name AND process.name:$process.name"
        alert_data = {
            "user": {"name": "john.doe"},
            "process": {"name": "malware.exe"}
        }
        
        result = playbook_tools._substitute_variables(query, alert_data)
        
        assert result == "user.name:john.doe AND process.name:malware.exe"
    
    def test_substitute_variables_with_spaces(self):
        """Test variable substitution with values containing spaces."""
        query = "message:{{alert.message}}"
        alert_data = {
            "alert": {"message": "Suspicious activity detected"}
        }
        
        result = playbook_tools._substitute_variables(query, alert_data)
        
        assert result == 'message:"Suspicious activity detected"'
    
    def test_substitute_variables_missing_field(self):
        """Test variable substitution when field is missing."""
        query = "source.ip:{{source.ip}} AND missing:{{missing.field}}"
        alert_data = {
            "source": {"ip": "10.0.0.1"}
        }
        
        result = playbook_tools._substitute_variables(query, alert_data)
        
        # Should keep the original placeholder for missing fields
        assert result == "source.ip:10.0.0.1 AND missing:{{missing.field}}"
    
    def test_substitute_variables_special_characters(self):
        """Test variable substitution with special characters that need escaping."""
        query = "path:{{file.path}}"
        alert_data = {
            "file": {"path": "C:\\Windows\\System32\\cmd.exe"}
        }
        
        result = playbook_tools._substitute_variables(query, alert_data)
        
        # Backslashes should be escaped (no quotes because no spaces)
        assert result == 'path:C\\:\\\\Windows\\\\System32\\\\cmd.exe'
    
    def test_parse_time_range_plus_minus(self):
        """Test parsing +/-Xd format time ranges."""
        base_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        alert_timestamp = base_time.isoformat()
        
        start, end = playbook_tools._parse_time_range("+/-3d", alert_timestamp)
        
        # Should be 3 days before and 3 days after
        assert "2024-01-12" in start
        assert "2024-01-18" in end
    
    def test_parse_time_range_split_format(self):
        """Test parsing -Xh/+Yh format time ranges."""
        base_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        alert_timestamp = base_time.isoformat()
        
        start, end = playbook_tools._parse_time_range("-2h/+1h", alert_timestamp)
        
        # Should be 2 hours before and 1 hour after
        assert "2024-01-15T10:00:00" in start
        assert "2024-01-15T13:00:00" in end
    
    def test_parse_time_range_default(self):
        """Test default time range when none specified."""
        base_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        alert_timestamp = base_time.isoformat()
        
        start, end = playbook_tools._parse_time_range("", alert_timestamp)
        
        # Default should be +/- 1 hour
        assert "2024-01-15T11:00:00" in start
        assert "2024-01-15T13:00:00" in end
    
    def test_parse_time_range_no_alert_timestamp(self):
        """Test time range parsing when no alert timestamp provided."""
        # Should use current time
        start, end = playbook_tools._parse_time_range("+/-1d", None)
        
        # Just verify it returns ISO format strings
        assert "T" in start
        assert "T" in end
    
    @pytest.mark.asyncio
    async def test_execute_playbook_question_success(self):
        """Test successful execution of a playbook question."""
        question = {
            "question": "What is the source IP?",
            "context": "Identify the attacker",
            "query": "source.ip:{{source.ip}}",
            "range": "+/-1h",
            "answer_sources": ["network logs"]
        }
        
        alert_data = {"source": {"ip": "10.0.0.1"}}
        alert_timestamp = "2024-01-15T12:00:00Z"
        
        mock_results = [{"event": "test event"}]
        
        with patch('so_modules.event_query_tools.query_events_impl', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = mock_results
            
            result = await playbook_tools.execute_playbook_question(question, alert_data, alert_timestamp)
            
            assert result["question"] == "What is the source IP?"
            assert result["context"] == "Identify the attacker"
            assert result["answer_sources"] == ["network logs"]
            assert result["query"] == "source.ip:{{source.ip}}"
            assert result["executed_query"] == "source.ip:10.0.0.1"
            assert result["results"] == mock_results
            assert result["error"] is None
            
            # Verify query was called with correct parameters
            mock_query.assert_called_once()
            call_args = mock_query.call_args[1]
            assert call_args["oql_query"] == "source.ip:10.0.0.1"
            assert call_args["limit"] == 100
    
    @pytest.mark.asyncio
    async def test_execute_playbook_question_no_query(self):
        """Test execution when question has no query."""
        question = {
            "question": "Manual investigation required",
            "context": "Check manually"
        }
        
        result = await playbook_tools.execute_playbook_question(question, {}, None)
        
        assert result["error"] == "No query provided for this question"
        assert result["results"] == []
    
    @pytest.mark.asyncio
    async def test_execute_playbook_question_query_failure(self):
        """Test handling of query execution failure."""
        question = {
            "question": "Test question",
            "query": "test:query"
        }
        
        with patch('so_modules.event_query_tools.query_events_impl', new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = Exception("Query failed")
            
            result = await playbook_tools.execute_playbook_question(question, {}, None)
            
            assert result["error"] == "Query failed"
            assert result["results"] == []
    
    @pytest.mark.asyncio
    async def test_execute_playbook_impl_success(self):
        """Test successful playbook execution."""
        alert_id = "test-alert-123"
        
        mock_playbooks = [
            {
                "name": "Test Playbook",
                "description": "Test description",
                "questions": [
                    {
                        "question": "Q1",
                        "query": "test:query",
                        "range": "+/-1h"
                    }
                ]
            }
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_pb:
            with patch('so_modules.playbook_tools.execute_playbook_question', new_callable=AsyncMock) as mock_exec_q:
                mock_get_pb.return_value = mock_playbooks
                mock_exec_q.return_value = {
                    "question": "Q1",
                    "results": [{"test": "result"}],
                    "error": None
                }
                
                result = await playbook_tools.execute_playbook_impl(alert_id)
                
                assert result["alert_id"] == alert_id
                assert len(result["playbooks"]) == 1
                assert result["playbooks"][0]["name"] == "Test Playbook"
                assert len(result["playbooks"][0]["questions"]) == 1
    
    @pytest.mark.asyncio
    async def test_execute_playbook_impl_no_playbooks(self):
        """Test execution when no playbooks found."""
        alert_id = "test-alert-123"
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_pb:
            mock_get_pb.return_value = []
            
            result = await playbook_tools.execute_playbook_impl(alert_id)
            
            assert result["alert_id"] == alert_id
            assert result["error"] == "No playbooks found for this detection"
            assert result["playbooks"] == []
    
    @pytest.mark.asyncio
    async def test_execute_playbook_impl_specific_index(self):
        """Test execution of specific playbook by index."""
        alert_id = "test-alert-123"
        
        mock_playbooks = [
            {"name": "Playbook 1", "questions": []},
            {"name": "Playbook 2", "questions": []},
            {"name": "Playbook 3", "questions": []}
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_pb:
            with patch('so_modules.event_query_tools.query_events_impl', new_callable=AsyncMock) as mock_query:
                mock_get_pb.return_value = mock_playbooks
                mock_query.return_value = []
                
                # Execute only the second playbook (index 1)
                result = await playbook_tools.execute_playbook_impl(alert_id, playbook_index=1)
                
                assert len(result["playbooks"]) == 1
                assert result["playbooks"][0]["name"] == "Playbook 2"
    
    @pytest.mark.asyncio
    async def test_execute_playbook_impl_invalid_index(self):
        """Test execution with invalid playbook index."""
        alert_id = "test-alert-123"
        
        mock_playbooks = [{"name": "Playbook 1"}]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_pb:
            mock_get_pb.return_value = mock_playbooks
            
            result = await playbook_tools.execute_playbook_impl(alert_id, playbook_index=5)
            
            assert result["error"] == "Invalid playbook index. Found 1 playbooks."
    
    @pytest.mark.asyncio
    async def test_execute_playbook_impl_fetch_alert_data(self):
        """Test automatic fetching of alert data when not provided."""
        alert_id = "test-alert-123"
        mock_alert_data = {
            "event": {"id": alert_id},
            "@timestamp": "2024-01-15T12:00:00Z",
            "source": {"ip": "10.0.0.1"}
        }
        
        mock_playbooks = [
            {
                "name": "Test Playbook",
                "questions": [
                    {
                        "question": "Source IP?",
                        "query": "source.ip:{{source.ip}}"
                    }
                ]
            }
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_pb:
            with patch('so_modules.event_query_tools.query_events_impl', new_callable=AsyncMock) as mock_query:
                mock_get_pb.return_value = mock_playbooks
                
                # First call fetches the alert, second executes the playbook query
                mock_query.side_effect = [
                    [mock_alert_data],  # Alert fetch result
                    [{"result": "data"}]  # Playbook query result
                ]
                
                result = await playbook_tools.execute_playbook_impl(alert_id)
                
                # Should have made two query calls
                assert mock_query.call_count == 2
                
                # First call should search for the alert
                first_call = mock_query.call_args_list[0][1]
                assert alert_id in first_call["oql_query"]
                
                # Second call should have substituted the IP
                second_call = mock_query.call_args_list[1][1]
                assert "source.ip:10.0.0.1" in second_call["oql_query"]
    
    @pytest.mark.asyncio
    async def test_execute_playbook_impl_exception_handling(self):
        """Test handling of exceptions during playbook execution."""
        alert_id = "test-alert-123"
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_pb:
            mock_get_pb.side_effect = Exception("API Error")
            
            result = await playbook_tools.execute_playbook_impl(alert_id)
            
            assert result["alert_id"] == alert_id
            assert result["error"] == "API Error"
            assert result["playbooks"] == []