# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
from unittest import mock
import importlib
import os
import sys

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

def test_main_execution(mock_env_vars):
    """Test the actual execution in the __main__ block."""
    # Import the module
    import security_onion_server
    
    # Mock asyncio.run to prevent actual execution
    with mock.patch('asyncio.run') as mock_run:
        # Set __name__ to "__main__" to trigger the if block
        original_name = security_onion_server.__name__
        security_onion_server.__name__ = "__main__"
        
        try:
            # Re-execute the module code
            exec(open(security_onion_server.__file__).read(), security_onion_server.__dict__)
            
            # Verify that asyncio.run was called with the result of run()
            mock_run.assert_called_once()
            # The first argument to mock_run should be a coroutine object
            args, _ = mock_run.call_args
            assert len(args) == 1
            # Check that the argument is a coroutine (has __await__ method)
            assert hasattr(args[0], '__await__')
        finally:
            # Restore the original name
            security_onion_server.__name__ = original_name