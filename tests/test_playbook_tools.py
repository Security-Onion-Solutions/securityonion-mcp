# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
from unittest.mock import Mock, patch, AsyncMock
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
                        "query": "source.ip:{source.ip}",
                        "context": "Identifying the source",
                        "range": "+/-1h",
                        "answer_sources": ["network logs"]
                    }
                ]
            }
        ]
        
        with patch('so_modules.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_playbooks
            
            result = await playbook_tools.get_playbooks_for_detection("test-detection-id")
            
            assert result == mock_playbooks
            mock_api.assert_called_once_with("/connect/playbook/detection/test-detection-id", params={})
    
    @pytest.mark.asyncio
    async def test_get_playbooks_for_detection_failure(self):
        """Test handling of API failure when retrieving playbooks."""
        with patch('so_modules.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.side_effect = Exception("API Error")
            
            with pytest.raises(Exception) as exc_info:
                await playbook_tools.get_playbooks_for_detection("test-detection-id")
            
            assert str(exc_info.value) == "API Error"
    
    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_success(self):
        """Test successful retrieval of playbook questions."""
        mock_playbooks = [
            {
                "name": "Investigation Playbook",
                "description": "Standard investigation",
                "questions": [
                    {
                        "question": "Is the source IP internal or external?",
                        "context": "Helps determine if this is lateral movement",
                        "query": "source.ip:{source.ip}",
                        "range": "+/-3h",
                        "answer_sources": ["network logs", "firewall logs"]
                    },
                    {
                        "question": "What DNS queries were made?",
                        "context": "Check for C2 communication",
                        "query": "dns.query.name:*",
                        "range": "+/-1h"
                    }
                ]
            }
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_playbooks
            
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            
            assert result["alert_id"] == "test-alert"
            assert len(result["playbooks"]) == 1
            assert result["playbooks"][0]["name"] == "Investigation Playbook"
            assert len(result["playbooks"][0]["questions"]) == 2
            
            # Check first question
            q1 = result["playbooks"][0]["questions"][0]
            assert q1["question"] == "Is the source IP internal or external?"
            assert q1["context"] == "Helps determine if this is lateral movement"
            assert q1["suggested_query"] == "source.ip:{source.ip}"
            assert q1["time_range"] == "+/-3h"
            assert q1["answer_sources"] == ["network logs", "firewall logs"]
            
            # Check second question (without answer_sources)
            q2 = result["playbooks"][0]["questions"][1]
            assert q2["answer_sources"] == []
    
    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_no_playbooks(self):
        """Test when no playbooks are found."""
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = []
            
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            
            assert result["alert_id"] == "test-alert"
            assert result["error"] == "No playbooks found for this detection"
            assert result["playbooks"] == []
    
    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_specific_index(self):
        """Test getting questions from a specific playbook by index."""
        mock_playbooks = [
            {"name": "Playbook 1", "questions": [{"question": "Q1"}]},
            {"name": "Playbook 2", "questions": [{"question": "Q2"}]},
            {"name": "Playbook 3", "questions": [{"question": "Q3"}]}
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_playbooks
            
            result = await playbook_tools.get_playbook_questions_impl("test-alert", playbook_index=1)
            
            assert len(result["playbooks"]) == 1
            assert result["playbooks"][0]["name"] == "Playbook 2"
    
    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_invalid_index(self):
        """Test with invalid playbook index."""
        mock_playbooks = [{"name": "Playbook 1"}]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_playbooks
            
            result = await playbook_tools.get_playbook_questions_impl("test-alert", playbook_index=5)
            
            assert result["error"] == "Invalid playbook index. Found 1 playbooks."
    
    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_exception_handling(self):
        """Test exception handling."""
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = Exception("API Error")
            
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            
            assert result["alert_id"] == "test-alert"
            assert result["error"] == "API Error"
            assert result["playbooks"] == []
    
    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_missing_fields(self):
        """Test handling of playbooks with missing fields."""
        mock_playbooks = [
            {
                # Missing name and description
                "questions": [
                    {
                        # Missing most fields
                        "question": "Basic question"
                    }
                ]
            }
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_playbooks
            
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            
            assert result["playbooks"][0]["name"] == "Unnamed Playbook"
            assert result["playbooks"][0]["description"] == ""
            
            question = result["playbooks"][0]["questions"][0]
            assert question["question"] == "Basic question"
            assert question["context"] == ""
            assert question["answer_sources"] == []
            assert question["suggested_query"] == ""
            assert question["time_range"] == "+/-1h"  # Default
    
    @pytest.mark.asyncio
    async def test_get_playbooks_empty_response(self):
        """Test handling of non-list response from API."""
        with patch('so_modules.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            # Return non-list response
            mock_api.return_value = {"error": "not found"}
            
            result = await playbook_tools.get_playbooks_for_detection("test-id")
            
            # Should return empty list for non-list responses
            assert result == []