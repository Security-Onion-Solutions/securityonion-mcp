# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""Additional tests for playbook_tools to ensure 100% coverage."""

import pytest
from unittest.mock import patch, AsyncMock
from so_modules import playbook_tools


class TestPlaybookToolsCoverage:
    """Additional test cases for complete coverage of playbook_tools module."""
    
    @pytest.mark.asyncio
    async def test_get_playbooks_api_exception(self):
        """Test handling of API exception in get_playbooks_for_detection."""
        with patch('so_modules.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.side_effect = Exception("API connection failed")
            
            with pytest.raises(Exception) as exc_info:
                await playbook_tools.get_playbooks_for_detection("test-id")
            
            assert str(exc_info.value) == "API connection failed"
    
    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_empty_questions(self):
        """Test playbook with empty questions list."""
        mock_playbooks = [
            {
                "name": "Empty Playbook",
                "description": "A playbook with no questions",
                "questions": []
            }
        ]
        
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_playbooks
            
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            
            assert result["alert_id"] == "test-alert"
            assert len(result["playbooks"]) == 1
            assert result["playbooks"][0]["name"] == "Empty Playbook"
            assert result["playbooks"][0]["questions"] == []
    
    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_non_list_response(self):
        """Test handling when API returns non-list response."""
        # Test case where API returns non-list response, which get_playbooks_for_detection converts to []
        with patch('so_modules.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = {"error": "not found"}
            
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            
            assert result["alert_id"] == "test-alert"
            assert result["error"] == "No playbooks found for this detection"
            assert result["playbooks"] == []