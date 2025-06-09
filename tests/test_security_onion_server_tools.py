# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""Tests for the MCP tool functions in security_onion_server.py"""

import pytest
from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_execute_playbook_tool():
    """Test the execute_playbook MCP tool function directly."""
    # Import the function after environment is set up
    from security_onion_server import execute_playbook
    
    # Mock the implementation
    with patch('so_modules.playbook_tools.execute_playbook_impl', new_callable=AsyncMock) as mock_impl:
        mock_impl.return_value = {
            "alert_id": "test-123",
            "playbooks": [
                {
                    "name": "Test Playbook",
                    "questions": [
                        {"question": "Q1", "results": []}
                    ]
                }
            ]
        }
        
        # Test with all parameters
        result = await execute_playbook(
            alert_id="test-123",
            alert_data={"source": {"ip": "10.0.0.1"}},
            playbook_index=0
        )
        
        # Verify the result
        assert result["alert_id"] == "test-123"
        assert len(result["playbooks"]) == 1
        
        # Verify the implementation was called correctly
        mock_impl.assert_called_once_with(
            alert_id="test-123",
            alert_data={"source": {"ip": "10.0.0.1"}},
            playbook_index=0
        )


@pytest.mark.asyncio
async def test_execute_playbook_tool_minimal():
    """Test the execute_playbook MCP tool with minimal parameters."""
    from security_onion_server import execute_playbook
    
    with patch('so_modules.playbook_tools.execute_playbook_impl', new_callable=AsyncMock) as mock_impl:
        mock_impl.return_value = {"alert_id": "test-456", "playbooks": []}
        
        # Test with only required parameter
        result = await execute_playbook(alert_id="test-456")
        
        # Verify
        assert result["alert_id"] == "test-456"
        
        # Should be called with None for optional parameters
        mock_impl.assert_called_once_with(
            alert_id="test-456",
            alert_data=None,
            playbook_index=None
        )