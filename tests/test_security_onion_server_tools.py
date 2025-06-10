# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""Tests for the MCP tool functions in security_onion_server.py"""

import pytest
from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_get_playbook_questions_tool():
    """Test the get_playbook_questions MCP tool function directly."""
    # Import the function after environment is set up
    from security_onion_server import get_playbook_questions
    
    # Mock the implementation
    with patch('so_modules.playbook_tools.get_playbook_questions_impl', new_callable=AsyncMock) as mock_impl:
        mock_impl.return_value = {
            "alert_id": "test-123",
            "playbooks": [
                {
                    "name": "Test Playbook",
                    "description": "Test description",
                    "questions": [
                        {
                            "question": "What is the source IP?",
                            "context": "Identify the source",
                            "answer_sources": ["network logs"],
                            "suggested_query": "source.ip:*",
                            "time_range": "+/-1h"
                        }
                    ]
                }
            ]
        }
        
        # Test with all parameters
        result = await get_playbook_questions(
            alert_id="test-123",
            playbook_index=0
        )
        
        # Verify the result
        assert result["alert_id"] == "test-123"
        assert len(result["playbooks"]) == 1
        assert result["playbooks"][0]["name"] == "Test Playbook"
        
        # Verify the implementation was called correctly
        mock_impl.assert_called_once_with(
            alert_id="test-123",
            playbook_index=0
        )


@pytest.mark.asyncio
async def test_get_playbook_questions_tool_minimal():
    """Test the get_playbook_questions MCP tool with minimal parameters."""
    from security_onion_server import get_playbook_questions
    
    with patch('so_modules.playbook_tools.get_playbook_questions_impl', new_callable=AsyncMock) as mock_impl:
        mock_impl.return_value = {
            "alert_id": "test-456",
            "error": "No playbooks found for this detection",
            "playbooks": []
        }
        
        # Test with only required parameter
        result = await get_playbook_questions(alert_id="test-456")
        
        # Verify
        assert result["alert_id"] == "test-456"
        assert result["error"] == "No playbooks found for this detection"
        
        # Should be called with None for optional parameters
        mock_impl.assert_called_once_with(
            alert_id="test-456",
            playbook_index=None
        )