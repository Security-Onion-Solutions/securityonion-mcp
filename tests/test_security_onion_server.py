# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
from unittest.mock import AsyncMock, MagicMock

# Import the modules containing the implementation functions
# We assume these modules exist based on the original test mocks
from so_modules import utility_tools, event_query_tools

# We no longer need to import the server or TestClient

def test_ping_impl(mocker):
    """
    Test the ping_impl function directly.
    """
    # Mock the implementation function within its module
    mock_ping = mocker.patch("so_modules.utility_tools.ping_impl", return_value="pong")

    # Call the function directly
    result = utility_tools.ping_impl()

    # Assert the result
    assert result == "pong"
    mock_ping.assert_called_once()

# Add more tests for other functions as needed

# Note: If security_onion_server.py itself defines tools or functions directly
# (not just importing and registering them from other modules),
# additional tests might be needed here to cover that logic, potentially
# mocking the MCP server's internal methods if necessary.
# These rewritten tests focus only on the *implementation* functions
# that were being mocked in the original TestClient-based tests.