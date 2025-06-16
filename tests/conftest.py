# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import os
import pytest
import importlib
from unittest import mock

# Fixture to ensure environment variables are properly loaded
@pytest.fixture(scope="session", autouse=True)
def ensure_env_vars():
    """
    Ensure environment variables are properly loaded from pytest.ini.
    This fixture applies to all tests automatically.
    """
    # Set default environment variables for testing if not already set
    if not os.getenv("SO_CLIENT_ID"):
        os.environ["SO_CLIENT_ID"] = "test_client_id"
    if not os.getenv("SO_CLIENT_SECRET"):
        os.environ["SO_CLIENT_SECRET"] = "test_client_secret"
    if not os.getenv("SO_API_ENDPOINT"):
        os.environ["SO_API_ENDPOINT"] = "https://test.api.endpoint"
    
    # Reload the config module to pick up the environment variables
    try:
        from so_modules import config
        importlib.reload(config)
    except ImportError:  # pragma: no cover
        # The config module might not be imported yet
        pass
    
    yield