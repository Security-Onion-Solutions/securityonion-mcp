# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
import requests
from unittest.mock import MagicMock, patch, AsyncMock
import json

# Assuming config is setup correctly elsewhere or mocked if needed for tests
from so_modules import api, config

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio

# --- Tests for get_so_token ---

@pytest.fixture(autouse=True)
def mock_config(mocker):
    """Auto-used fixture to mock config variables for all tests."""
    mocker.patch.object(config, 'SO_CLIENT_ID', 'test_client_id')
    mocker.patch.object(config, 'SO_CLIENT_SECRET', 'test_client_secret')
    mocker.patch.object(config, 'SO_API_ENDPOINT', 'http://test.so.api')
    mocker.patch.object(config, 'SO_API_VERIFY_SSL', False)
    # Mock check_config to prevent it from actually raising errors during tests
    mocker.patch.object(config, 'check_config')


async def test_get_so_token_success(mocker):
    """Test successful retrieval of the SO API token."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"access_token": "fake_token_123"}
    mock_response.raise_for_status = MagicMock() # Does nothing on success

    # Mock asyncio.to_thread which wraps requests.post
    mock_async_post = AsyncMock(return_value=mock_response)
    mocker.patch('asyncio.to_thread', mock_async_post)

    token = await api.get_so_token()

    assert token == "fake_token_123"
    mock_async_post.assert_called_once()
    # Check args passed to requests.post via asyncio.to_thread
    call_args, call_kwargs = mock_async_post.call_args
    # Positional args passed to asyncio.to_thread
    assert call_args[0] == requests.post # The function to run in the thread
    assert call_args[1] == f"{config.SO_API_ENDPOINT}/oauth2/token" # The first arg to requests.post (url)
    # Keyword args passed through to requests.post
    assert call_kwargs['auth'] == (config.SO_CLIENT_ID, config.SO_CLIENT_SECRET)
    assert call_kwargs['data'] == {"grant_type": "client_credentials"}
    assert call_kwargs['verify'] is False


async def test_get_so_token_request_exception(mocker):
    """Test handling of RequestException during token retrieval."""
    # Mock asyncio.to_thread to raise RequestException
    mock_async_post = AsyncMock(side_effect=requests.exceptions.RequestException("Network Error"))
    mocker.patch('asyncio.to_thread', mock_async_post)

    with pytest.raises(Exception, match="Failed to retrieve Security Onion API token due to a network or request error."):
        await api.get_so_token()


async def test_get_so_token_http_error(mocker):
    """Test handling of HTTP error status codes."""
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Unauthorized")

    mock_async_post = AsyncMock(return_value=mock_response)
    mocker.patch('asyncio.to_thread', mock_async_post)

    with pytest.raises(Exception, match="Failed to retrieve Security Onion API token due to a network or request error."):
        await api.get_so_token()
    mock_response.raise_for_status.assert_called_once()


async def test_get_so_token_json_decode_error(mocker):
    """Test handling of JSONDecodeError when parsing the token response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "invalid json"
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "invalid json", 0)
    mock_response.raise_for_status = MagicMock()

    mock_async_post = AsyncMock(return_value=mock_response)
    mocker.patch('asyncio.to_thread', mock_async_post)

    with pytest.raises(Exception, match="Received an invalid response when retrieving Security Onion API token."):
        await api.get_so_token()


async def test_get_so_token_missing_access_token_key(mocker):
    """Test handling when 'access_token' key is missing in the response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"token_type": "bearer"} # Missing access_token
    mock_response.raise_for_status = MagicMock()

    mock_async_post = AsyncMock(return_value=mock_response)
    mocker.patch('asyncio.to_thread', mock_async_post)

    # The function explicitly raises KeyError which is *not* caught by the generic handlers
    with pytest.raises(KeyError, match="access_token not found in response"):
         await api.get_so_token()


async def test_get_so_token_config_check_called(mocker):
    """Test that config.check_config is called if config is initially missing."""
    # Temporarily unset a required config var
    mocker.patch.object(config, 'SO_CLIENT_ID', None)
    mock_check_config = mocker.patch.object(config, 'check_config', side_effect=ValueError("Config missing"))

    with pytest.raises(ValueError, match="Config missing"): # Expect the error from check_config
        await api.get_so_token()

    mock_check_config.assert_called_once()


# --- Tests for make_so_api_request ---

@pytest.fixture
def mock_get_token(mocker):
    """Fixture to mock the get_so_token dependency."""
    return mocker.patch('so_modules.api.get_so_token', new_callable=AsyncMock, return_value="mock_token_456")


async def test_make_so_api_request_success(mocker, mock_get_token):
    """Test successful API GET request."""
    endpoint = "/api/test/endpoint"
    params = {"query": "value"}
    expected_response_data = {"result": "success", "data": [1, 2, 3]}

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = expected_response_data
    mock_response.raise_for_status = MagicMock()

    mock_async_get = AsyncMock(return_value=mock_response)
    mocker.patch('asyncio.to_thread', mock_async_get) # Mocks the call to requests.get

    response_data = await api.make_so_api_request(endpoint, params.copy()) # Pass copy to check defaults later

    assert response_data == expected_response_data
    mock_get_token.assert_called_once()
    mock_async_get.assert_called_once()

    # Check args passed to requests.get via asyncio.to_thread
    call_args, call_kwargs = mock_async_get.call_args
    assert call_args[0] == requests.get # Function called
    assert call_args[1] == f"{config.SO_API_ENDPOINT}{endpoint}" # url
    assert call_kwargs['headers'] == {"Authorization": "Bearer mock_token_456"}

    # Check that default params were added
    expected_params = {
        "query": "value",
        "zone": "America/New_York",
        "format": "2006/01/02 3:04:05 PM",
        "metricLimit": "10",
        "eventLimit": "10"
    }
    assert call_kwargs['params'] == expected_params
    assert call_kwargs['verify'] is False


async def test_make_so_api_request_request_exception(mocker, mock_get_token):
    """Test handling of RequestException during API GET request."""
    endpoint = "/api/fail"
    params = {}

    # Mock asyncio.to_thread to raise RequestException
    mock_async_get = AsyncMock(side_effect=requests.exceptions.RequestException("Connection Timeout"))
    mocker.patch('asyncio.to_thread', mock_async_get)

    with pytest.raises(Exception, match=f"Security Onion API request failed for endpoint '{endpoint}' due to a network or request error."):
        await api.make_so_api_request(endpoint, params)

    mock_get_token.assert_called_once() # Token retrieval happens first


async def test_make_so_api_request_http_error(mocker, mock_get_token):
    """Test handling of HTTP error status codes during API GET request."""
    endpoint = "/api/unauthorized"
    params = {}

    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Forbidden")

    mock_async_get = AsyncMock(return_value=mock_response)
    mocker.patch('asyncio.to_thread', mock_async_get)

    with pytest.raises(Exception, match=f"Security Onion API request failed for endpoint '{endpoint}' due to a network or request error."):
        await api.make_so_api_request(endpoint, params)

    mock_get_token.assert_called_once()
    mock_response.raise_for_status.assert_called_once()


async def test_make_so_api_request_json_decode_error(mocker, mock_get_token):
    """Test handling of JSONDecodeError when parsing the API response."""
    endpoint = "/api/badjson"
    params = {}

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<html><body>Error</body></html>"
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", mock_response.text, 0)
    mock_response.raise_for_status = MagicMock()

    mock_async_get = AsyncMock(return_value=mock_response)
    mocker.patch('asyncio.to_thread', mock_async_get)

    with pytest.raises(Exception, match=f"Received an invalid response from Security Onion API endpoint '{endpoint}'."):
        await api.make_so_api_request(endpoint, params)

    mock_get_token.assert_called_once()


async def test_make_so_api_request_config_check_called(mocker):
    """Test that config.check_config is called if SO_API_ENDPOINT is missing."""
    # Unset the endpoint specifically for this test
    mocker.patch.object(config, 'SO_API_ENDPOINT', None)
    mock_check_config = mocker.patch.object(config, 'check_config', side_effect=ValueError("Endpoint missing"))
    # Mock get_so_token as it would be called *after* the config check if it passed
    mocker.patch('so_modules.api.get_so_token', new_callable=AsyncMock)

    with pytest.raises(ValueError, match="Endpoint missing"):
        await api.make_so_api_request("/api/whatever", {})

    mock_check_config.assert_called_once()
    api.get_so_token.assert_not_called() # Should fail before trying to get token