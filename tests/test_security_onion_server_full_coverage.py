# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock
from unittest.mock import patch
import os
import importlib
import logging
from unittest import mock
import sys
import asyncio
import mcp.types as types

# We need to import the server module in each test function to control the environment
# variables before import

@pytest.fixture
def mock_env_vars():
    """Setup environment variables for tests."""
    # Save original environment variables
    original_vars = {}
    for var in ["SO_CLIENT_ID", "SO_CLIENT_SECRET", "SO_API_ENDPOINT", "SO_ENABLE_FILE_LOGGING"]:
        original_vars[var] = os.environ.get(var)
    
    # Set test environment variables
    os.environ["SO_CLIENT_ID"] = "test_client_id"
    os.environ["SO_CLIENT_SECRET"] = "test_client_secret"
    os.environ["SO_API_ENDPOINT"] = "https://test.api.endpoint"
    
    yield
    
    # Restore original environment variables
    for var, value in original_vars.items():
        if value is not None:
            os.environ[var] = value
        elif var in os.environ:
            del os.environ[var]

@pytest.mark.asyncio
async def test_get_capabilities_real_implementation(mock_env_vars):
    """Test the get_capabilities function with real implementation."""
    import security_onion_server
    
    # Create a mock tool for server.list_tools to return
    mock_tool = mock.MagicMock()
    mock_tool.model_dump.return_value = {"name": "test_tool"}
    
    # Mock the server.list_tools method to return our mock tool
    original_list_tools = security_onion_server.server.list_tools
    security_onion_server.server.list_tools = mock.AsyncMock(return_value=[mock_tool])
    
    try:
        # Call the function
        capabilities = await security_onion_server.get_capabilities()
        
        # Verify the result
        assert capabilities is not None
        assert isinstance(capabilities, types.ServerCapabilities)
        assert hasattr(capabilities, "tools")
        assert len(capabilities.tools.tools) == 1
        assert capabilities.tools.tools[0] == {"name": "test_tool"}
        
        # Verify that server.list_tools was called
        security_onion_server.server.list_tools.assert_called_once()
        
        # Verify that model_dump was called on the tool
        mock_tool.model_dump.assert_called_once_with(exclude_none=True)
    finally:
        # Restore the original method
        security_onion_server.server.list_tools = original_list_tools

def test_ping_real_implementation(mock_env_vars):
    """Test the ping tool with real implementation."""
    import security_onion_server
    from so_modules import utility_tools
    
    # Save the original implementation
    original_ping_impl = utility_tools.ping_impl
    
    try:
        # Call the function directly
        result = security_onion_server.ping()
        
        # Verify the result
        assert result == "pong"
    finally:
        # Restore the original function
        utility_tools.ping_impl = original_ping_impl

@pytest.mark.asyncio
async def test_query_events_real_implementation(mock_env_vars):
    """Test the query_events tool with real implementation."""
    import security_onion_server
    from so_modules import event_query_tools
    
    # Mock the implementation function
    original_query_events_impl = event_query_tools.query_events_impl
    mock_result = [{"event": "test_event"}]
    event_query_tools.query_events_impl = mock.AsyncMock(return_value=mock_result)
    
    try:
        # Call the function directly
        result = await security_onion_server.query_events(
            oql_query="test_query",
            start_time="-1h",
            end_time="now",
            limit=10,
            groupby_field="test_field"
        )
        
        # Verify the result
        assert result == mock_result
        
        # Verify that query_events_impl was called with the correct arguments
        event_query_tools.query_events_impl.assert_called_once_with(
            oql_query="test_query",
            start_time="-1h",
            end_time="now",
            limit=10,
            groupby_field="test_field"
        )
    finally:
        # Restore the original function
        event_query_tools.query_events_impl = original_query_events_impl

@pytest.mark.asyncio
async def test_run_with_invalid_config_main_module(mock_env_vars):
    """Test the run function when configuration is invalid and running as main module."""
    import security_onion_server
    
    # Mock the check_configuration function to return False
    original_check_configuration = security_onion_server.check_configuration
    security_onion_server.check_configuration = mock.MagicMock(return_value=False)
    
    # Mock the server.run_stdio_async method
    original_run_stdio_async = security_onion_server.server.run_stdio_async
    security_onion_server.server.run_stdio_async = mock.AsyncMock()
    
    # Mock the __name__ attribute to simulate running as the main module
    original_name = security_onion_server.__name__
    security_onion_server.__name__ = "__main__"
    
    try:
        # Use pytest.raises to catch the SystemExit exception
        with pytest.raises(SystemExit) as excinfo:
            await security_onion_server.run()
        
        # Verify that the exit code is 1
        assert excinfo.value.code == 1
        
        # Verify that run_stdio_async was not called
        security_onion_server.server.run_stdio_async.assert_not_called()
    finally:
        # Restore the original methods and attributes
        security_onion_server.check_configuration = original_check_configuration
        security_onion_server.server.run_stdio_async = original_run_stdio_async
        security_onion_server.__name__ = original_name

@pytest.mark.asyncio
async def test_run_with_invalid_config_not_main_module(mock_env_vars):
    """Test the run function when configuration is invalid and not running as main module."""
    import security_onion_server
    
    # Mock the check_configuration function to return False
    original_check_configuration = security_onion_server.check_configuration
    security_onion_server.check_configuration = mock.MagicMock(return_value=False)
    
    # Mock the server.run_stdio_async method
    original_run_stdio_async = security_onion_server.server.run_stdio_async
    security_onion_server.server.run_stdio_async = mock.AsyncMock()
    
    # Ensure __name__ is not "__main__"
    original_name = security_onion_server.__name__
    security_onion_server.__name__ = "security_onion_server"
    
    try:
        # This should return early without calling run_stdio_async
        result = await security_onion_server.run()
        
        # Verify that the result is None
        assert result is None
        
        # Verify that run_stdio_async was not called
        security_onion_server.server.run_stdio_async.assert_not_called()
    finally:
        # Restore the original methods and attributes
        security_onion_server.check_configuration = original_check_configuration
        security_onion_server.server.run_stdio_async = original_run_stdio_async
        security_onion_server.__name__ = original_name

@pytest.mark.asyncio
async def test_run_with_valid_config(mock_env_vars):
    """Test the run function when configuration is valid."""
    import security_onion_server
    
    # Mock the check_configuration function to return True
    original_check_configuration = security_onion_server.check_configuration
    security_onion_server.check_configuration = mock.MagicMock(return_value=True)
    
    # Mock the server.run_stdio_async method
    original_run_stdio_async = security_onion_server.server.run_stdio_async
    security_onion_server.server.run_stdio_async = mock.AsyncMock()
    
    try:
        # Call the function
        await security_onion_server.run()
        
        # Verify that check_configuration was called
        security_onion_server.check_configuration.assert_called_once()
        
        # Verify that run_stdio_async was called
        security_onion_server.server.run_stdio_async.assert_called_once()
    finally:
        # Restore the original methods
        security_onion_server.check_configuration = original_check_configuration
        security_onion_server.server.run_stdio_async = original_run_stdio_async
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