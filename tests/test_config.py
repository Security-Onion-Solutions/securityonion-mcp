# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import os
import pytest
from unittest import mock
import importlib  # To reload the module

# Import the modules we are testing
import so_modules.config as config


# --- Tests for SO_CA_CERT ---

@mock.patch.dict(os.environ, {}, clear=True)
def test_so_ca_cert():
    """Tests that SO_CA_CERT is read from the environment."""
    # Test when the variable is set
    os.environ["SO_CA_CERT"] = "/path/to/cert.pem"
    importlib.reload(config)
    assert config.SO_CA_CERT == "/path/to/cert.pem"

    # Test when the variable is not set
    del os.environ["SO_CA_CERT"]
    importlib.reload(config)
    assert config.SO_CA_CERT is None


# --- Tests for SO_API_VERIFY_SSL ---

@pytest.mark.parametrize(
    "env_value, expected_result",
    [
        (None, True),  # Default when not set
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("YES", True),
        ("false", False),
        ("FALSE", False),
        ("0", False),
        ("no", False),
        ("NO", False),
        ("random_string", True), # Default for unrecognized
        ("", True), # Default for empty string
    ],
)
@mock.patch.dict(os.environ, {}, clear=True) # Start with clean environment
def test_so_api_verify_ssl_logic(env_value, expected_result):
    """Tests the logic for setting SO_API_VERIFY_SSL based on env var."""
    if env_value is not None:
        os.environ["SO_API_VERIFY_SSL"] = env_value

    # Reload the config module to re-evaluate the environment variable
    importlib.reload(config)

    assert config.SO_API_VERIFY_SSL == expected_result



# --- Tests for check_config() ---

@mock.patch.dict(os.environ, {
    "SO_CLIENT_ID": "test_id",
    "SO_CLIENT_SECRET": "test_secret",
    "SO_API_ENDPOINT": "http://test.endpoint"
}, clear=True)
def test_check_config_success():
    """Tests check_config when all required variables are set."""
    # Reload config to pick up mocked env vars for constants
    importlib.reload(config)
    
    # Call check_config directly
    config.check_config()  # Should not raise an exception
    
    # If we get here, the test passes
    assert True

@pytest.mark.parametrize(
    "missing_vars, expected_message_part",
    [
        ({"SO_CLIENT_SECRET": "test_secret", "SO_API_ENDPOINT": "http://test.endpoint"}, "SO_CLIENT_ID"),
        ({"SO_CLIENT_ID": "test_id", "SO_API_ENDPOINT": "http://test.endpoint"}, "SO_CLIENT_SECRET"),
        ({"SO_CLIENT_ID": "test_id", "SO_CLIENT_SECRET": "test_secret"}, "SO_API_ENDPOINT"),
        ({}, "SO_CLIENT_ID, SO_CLIENT_SECRET, SO_API_ENDPOINT"), # All missing
    ]
)
@mock.patch.dict(os.environ, {}, clear=True) # Start clean
def test_check_config_failure(missing_vars, expected_message_part):
    """Tests check_config when required variables are missing."""
    # Set only the variables *not* intended to be missing for this test case
    os.environ.update(missing_vars)

    # Reload config to pick up mocked env vars for constants
    importlib.reload(config)

    with pytest.raises(ValueError) as excinfo:
        config.check_config()
    assert "Missing required environment variables:" in str(excinfo.value)
    assert expected_message_part in str(excinfo.value)