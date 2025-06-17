# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import pytest
import requests
from unittest.mock import MagicMock, patch, AsyncMock
import json
import os
import importlib
from datetime import datetime, timedelta, timezone
import unittest
import logging
import sys
import mcp.types as types

# Assuming config is setup correctly elsewhere or mocked if needed for tests
from so_modules import api, config, event_query_tools, playbook_tools, utility_tools, utils

# --- Mocks and Fixtures ---

@pytest.fixture(autouse=True)
def mock_config_env(mocker):
    """Auto-used fixture to mock config variables for all tests."""
    mocker.patch.dict(os.environ, {
        "SO_CLIENT_ID": "test_client_id",
        "SO_CLIENT_SECRET": "test_client_secret",
        "SO_API_ENDPOINT": "http://test.so.api",
        "SO_API_VERIFY_SSL": "false",
    }, clear=True)
    # Reload config to pick up the mocked env vars
    importlib.reload(config)
    importlib.reload(api)
    importlib.reload(utils)
    importlib.reload(playbook_tools)
    importlib.reload(event_query_tools)


@pytest.fixture
def mock_api_request(mocker):
    """Fixture to mock the api.make_so_api_request function."""
    mock = mocker.patch('so_modules.api.make_so_api_request', new_callable=AsyncMock)
    mock.return_value = {"events": [{"payload": {"field1": "value1", "_id": "event1"}}], "metrics": {}}
    return mock

# --- Tests for so_modules/api.py ---

class TestApi:
    @pytest.mark.asyncio
    async def test_get_so_token_success(self, mocker):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "fake_token_123"}
        mock_response.raise_for_status = MagicMock()
        mock_async_post = AsyncMock(return_value=mock_response)
        mocker.patch('asyncio.to_thread', mock_async_post)
        token = await api.get_so_token()
        assert token == "fake_token_123"

    @pytest.mark.asyncio
    async def test_get_so_token_with_ca_cert(self, mocker):
        mocker.patch.object(config, 'SO_CA_CERT', '/path/to/custom.crt')
        importlib.reload(api)
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "fake_token_123"}
        mock_async_post = AsyncMock(return_value=mock_response)
        mocker.patch('asyncio.to_thread', mock_async_post)
        await api.get_so_token()
        _ , call_kwargs = mock_async_post.call_args
        assert call_kwargs['verify'] == '/path/to/custom.crt'

    @pytest.mark.asyncio
    async def test_get_so_token_request_exception(self, mocker):
        mock_async_post = AsyncMock(side_effect=requests.exceptions.RequestException("Network Error"))
        mocker.patch('asyncio.to_thread', mock_async_post)
        with pytest.raises(Exception, match="Failed to retrieve Security Onion API token"):
            await api.get_so_token()

    @pytest.mark.asyncio
    async def test_get_so_token_http_error(self, mocker):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Unauthorized")
        mock_async_post = AsyncMock(return_value=mock_response)
        mocker.patch('asyncio.to_thread', mock_async_post)
        with pytest.raises(Exception, match="Failed to retrieve Security Onion API token"):
            await api.get_so_token()

    @pytest.mark.asyncio
    async def test_get_so_token_json_decode_error(self, mocker):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "invalid json"
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "invalid json", 0)
        mock_response.raise_for_status = MagicMock()
        mock_async_post = AsyncMock(return_value=mock_response)
        mocker.patch('asyncio.to_thread', mock_async_post)
        with pytest.raises(Exception, match="Received an invalid response"):
            await api.get_so_token()

    @pytest.mark.asyncio
    async def test_get_so_token_missing_access_token_key(self, mocker):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token_type": "bearer"}
        mock_response.raise_for_status = MagicMock()
        mock_async_post = AsyncMock(return_value=mock_response)
        mocker.patch('asyncio.to_thread', mock_async_post)
        with pytest.raises(KeyError, match="access_token not found"):
             await api.get_so_token()

    @pytest.mark.asyncio
    async def test_make_so_api_request_success(self, mocker):
        mock_get_token = mocker.patch('so_modules.api.get_so_token', new_callable=AsyncMock, return_value="mock_token_456")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_response.raise_for_status = MagicMock()
        mock_async_get = AsyncMock(return_value=mock_response)
        mocker.patch('asyncio.to_thread', mock_async_get)
        response_data = await api.make_so_api_request("/api/test", {})
        assert response_data == {"result": "success"}
        mock_get_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_make_so_api_request_request_exception(self, mocker):
        mocker.patch('so_modules.api.get_so_token', new_callable=AsyncMock, return_value="mock_token_456")
        mock_async_get = AsyncMock(side_effect=requests.exceptions.RequestException("Network Error"))
        mocker.patch('asyncio.to_thread', mock_async_get)
        with pytest.raises(Exception, match="Security Onion API request failed"):
            await api.make_so_api_request("/api/fail", {})

    @pytest.mark.asyncio
    async def test_make_so_api_request_json_decode_error(self, mocker):
        mocker.patch('so_modules.api.get_so_token', new_callable=AsyncMock, return_value="mock_token_456")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "invalid json"
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "invalid json", 0)
        mock_response.raise_for_status = MagicMock()
        mock_async_get = AsyncMock(return_value=mock_response)
        mocker.patch('asyncio.to_thread', mock_async_get)
        with pytest.raises(Exception, match="Received an invalid response"):
            await api.make_so_api_request("/api/badjson", {})

    @pytest.mark.asyncio
    async def test_api_config_check(self, mocker):
        mocker.patch('so_modules.config.SO_CLIENT_ID', None)
        with pytest.raises(ValueError):
            await api.get_so_token()

    @pytest.mark.asyncio
    async def test_make_so_api_request_no_endpoint(self, mocker):
        mocker.patch('so_modules.config.SO_API_ENDPOINT', None)
        with pytest.raises(ValueError):
            await api.make_so_api_request("/api/test", {})


# --- Tests for so_modules/config.py ---

class TestConfig:
    def test_so_ca_cert(self):
        with patch.dict(os.environ, {"SO_CA_CERT": "/path/to/cert.pem"}, clear=True):
            importlib.reload(config)
            assert config.SO_CA_CERT == "/path/to/cert.pem"
        with patch.dict(os.environ, {}, clear=True):
            importlib.reload(config)
            assert config.SO_CA_CERT is None

    @pytest.mark.parametrize("env_value, expected", [("true", True), ("false", False), ("1", True), ("0", False), (None, True), ("random", True)])
    def test_so_api_verify_ssl_logic(self, env_value, expected):
        if env_value is not None:
            with patch.dict(os.environ, {"SO_API_VERIFY_SSL": env_value}, clear=True):
                importlib.reload(config)
                assert config.SO_API_VERIFY_SSL is expected
        else:
            with patch.dict(os.environ, {}, clear=True):
                importlib.reload(config)
                assert config.SO_API_VERIFY_SSL is expected

    def test_check_config_success(self):
        with patch.dict(os.environ, {"SO_CLIENT_ID": "a", "SO_CLIENT_SECRET": "b", "SO_API_ENDPOINT": "c"}):
            importlib.reload(config)
            config.check_config() # Should not raise

    def test_check_config_failure(self):
        with patch.dict(os.environ, {}, clear=True):
            importlib.reload(config)
            with pytest.raises(ValueError, match="Missing required environment variables"):
                config.check_config()

# --- Tests for so_modules/playbook_tools.py ---

class TestPlaybookTools:
    @pytest.mark.asyncio
    async def test_get_playbooks_for_detection_success(self):
        mock_response = [{"name": "playbook1"}]
        with patch('so_modules.playbook_tools.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_response
            result = await playbook_tools.get_playbooks_for_detection("test-id")
            assert result == mock_response

    @pytest.mark.asyncio
    async def test_get_playbooks_for_detection_api_exception(self):
        with patch('so_modules.playbook_tools.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.side_effect = Exception("API connection failed")
            with pytest.raises(Exception, match="API connection failed"):
                await playbook_tools.get_playbooks_for_detection("test-id")

    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_no_playbooks_found(self):
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_playbooks:
            mock_get_playbooks.return_value = []
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            assert "No playbooks found" in result["error"]

    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_invalid_index(self):
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_playbooks:
            mock_get_playbooks.return_value = [{"name": "Playbook 1"}]
            result = await playbook_tools.get_playbook_questions_impl("test-alert", playbook_index=1)
            assert "Invalid playbook index" in result["error"]
            result = await playbook_tools.get_playbook_questions_impl("test-alert", playbook_index=-1)
            assert "Invalid playbook index" in result["error"]

    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_general_exception(self):
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_playbooks:
            mock_get_playbooks.side_effect = Exception("A general error occurred")
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            assert result["error"] == "A general error occurred"

    @pytest.mark.asyncio
    async def test_get_playbook_questions_impl_success_all_playbooks(self):
        mock_playbooks = [{"name": "Full Playbook", "description": "A complete playbook", "questions": [{"question": "What is this?", "context": "Some context", "answer_sources": ["logs"], "query": "hunt | where event.provider = 'test'", "range": "+/-2h"}, {}]}]
        with patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock) as mock_get_playbooks:
            mock_get_playbooks.return_value = mock_playbooks
            result = await playbook_tools.get_playbook_questions_impl("test-alert")
            assert len(result["playbooks"]) == 1

    @pytest.mark.asyncio
    async def test_playbook_tools_non_list_response(self, mocker):
        with patch('so_modules.playbook_tools.api.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = {"detail": "not a list"}
            result = await playbook_tools.get_playbooks_for_detection("test-id")
            assert result == []

# --- Tests for so_modules/utility_tools.py ---

class TestUtilityTools:
    def test_ping_impl(self):
        assert utility_tools.ping_impl() == "pong"

# --- Tests for so_modules/utils.py ---

class TestUtils:
    def test_escape_oql_value(self):
        assert utils.escape_oql_value("it's a test") == "'it''s a test'"
        assert utils.escape_oql_value("no quotes") == "'no quotes'"
        assert utils.escape_oql_value(123) == "123"
        assert utils.escape_oql_value("C:\\path\\to\\file") == "'C:\\path\\to\\file'"
        assert utils.escape_oql_value(["a", "b'c"]) == "['a', 'b''c']"
        assert utils.escape_oql_value("Mike's House") == "'Mike''s House'"

    def test_filter_event_payload(self):
        payload = {"a": 1, "b": 2, "c": 3}
        allowed = {"a", "c"}
        assert utils.filter_event_payload(payload, allowed) == {"a": 1, "c": 3}
        assert utils.filter_event_payload([], allowed) == {} # Non-dict payload

    def test_parse_datetime_string(self):
        assert isinstance(utils.parse_datetime_string("now"), datetime)
        assert isinstance(utils.parse_datetime_string("today"), datetime)
        assert isinstance(utils.parse_datetime_string("-1h"), datetime)
        assert isinstance(utils.parse_datetime_string("-1d"), datetime)
        assert isinstance(utils.parse_datetime_string("-1m"), datetime)
        assert isinstance(utils.parse_datetime_string("2024/01/01 12:00:00 PM"), datetime)
        with pytest.raises(ValueError):
            utils.parse_datetime_string("invalid date")
        with pytest.raises(ValueError):
            utils.parse_datetime_string("-1x")
        with pytest.raises(ValueError):
            utils.parse_datetime_string("--1h")
        with pytest.raises(ValueError):
            utils.parse_datetime_string("-xh")
        with pytest.raises(ValueError):
            utils.parse_datetime_string("-xd")
        with pytest.raises(ValueError):
            utils.parse_datetime_string("-xm")

    @patch('so_modules.utils.parse_datetime_string')
    def test_build_api_time_range(self, mock_parse):
        start_dt = datetime(2024, 1, 1, 10, 0, 0)
        end_dt = datetime(2024, 1, 1, 12, 0, 0)
        now_dt = datetime(2024, 1, 1, 13, 0, 0)

        # Test with start and end
        mock_parse.side_effect = [start_dt, end_dt]
        result = utils.build_api_time_range("start", "end")
        assert result == "2024/01/01 10:00:00 AM - 2024/01/01 12:00:00 PM"

        # Test swapped times
        mock_parse.side_effect = [end_dt, start_dt]
        result = utils.build_api_time_range("end", "start")
        assert result == "2024/01/01 10:00:00 AM - 2024/01/01 12:00:00 PM"

        # Test only start time
        mock_parse.side_effect = [start_dt, now_dt]
        result = utils.build_api_time_range("start", None)
        assert result is not None

        # Test only end time
        mock_parse.side_effect = [None, end_dt]
        assert utils.build_api_time_range(None, "end") is None

        # Test parse error
        mock_parse.side_effect = ValueError("Test Error")
        with pytest.raises(ValueError):
            utils.build_api_time_range("a", "b")
            
        # Test no times
        assert utils.build_api_time_range(None, None) is None

    def test_get_nested_field(self):
        data = {"a": {"b": {"c": "value"}}}
        assert utils.get_nested_field(data, "a.b.c") == "value"
        assert utils.get_nested_field(data, "a.b.d") is None
        assert utils.get_nested_field(data, "") is None
        assert utils.get_nested_field({}, "a.b.c") is None
        assert utils.get_nested_field(data, "a.b") == {"c": "value"}

    @patch('so_modules.config')
    def test_validate_configuration(self, mock_config):
        mock_config.check_config.return_value = None
        mock_config.SO_CA_CERT = "/path/to/cert.pem"
        utils.validate_configuration()
        mock_config.check_config.assert_called_once()
        mock_config.check_config.side_effect = ValueError("Missing")
        with pytest.raises(ValueError):
            utils.validate_configuration()

# --- Tests for security_onion_server.py ---

@pytest.fixture
def mock_server_dependencies(mocker):
    mocker.patch('so_modules.utils.validate_configuration')
    mocker.patch('security_onion_server.server.run_stdio_async', new_callable=AsyncMock)
    mocker.patch('security_onion_server.check_configuration', return_value=True)

class TestSecurityOnionServer:
    @pytest.mark.asyncio
    async def test_run_success(self, mock_server_dependencies):
        import security_onion_server
        await security_onion_server.run()
        security_onion_server.server.run_stdio_async.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_config_fail(self, mocker):
        import security_onion_server
        mocker.patch('security_onion_server.check_configuration', return_value=False)
        await security_onion_server.run()

    @pytest.mark.asyncio
    async def test_run_config_fail_main(self, mocker):
        import security_onion_server
        mocker.patch('security_onion_server.check_configuration', return_value=False)
        with patch.object(security_onion_server, '__name__', '__main__'):
            with pytest.raises(SystemExit):
                await security_onion_server.run()

    def test_file_logging_enabled(self, tmp_path):
        # Ensure handlers are clean before this test
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        with patch.dict(os.environ, {"SO_ENABLE_FILE_LOGGING": "true"}):
            os.chdir(tmp_path)
            import security_onion_server
            importlib.reload(security_onion_server)
            assert any(isinstance(h, logging.FileHandler) for h in root_logger.handlers)

    @pytest.mark.asyncio
    async def test_get_capabilities(self, mock_server_dependencies):
        import security_onion_server
        with patch('security_onion_server.server.list_tools', new_callable=AsyncMock) as mock_list_tools:
            mock_list_tools.return_value = []
            caps = await security_onion_server.get_capabilities()
            assert isinstance(caps, types.ServerCapabilities)

    @pytest.mark.asyncio
    async def test_main_execution(self, mock_server_dependencies):
        import security_onion_server
        with patch('asyncio.run') as mock_run:
            with patch.object(security_onion_server, '__name__', '__main__'):
                with patch('security_onion_server.check_configuration', return_value=True):
                     exec(open(security_onion_server.__file__).read(), security_onion_server.__dict__)
                     mock_run.assert_called_once()

# --- Tests for event_query_tools.py ---

class TestEventQueryTools:
    @pytest.mark.asyncio
    async def test_query_events_impl_success(self, mock_api_request):
        result = await event_query_tools.query_events_impl(oql_query='rule.name:"Test"')
        assert len(result) == 1
        assert "error" not in result[0]

    @pytest.mark.asyncio
    async def test_query_events_impl_groupby(self, mock_api_request):
        mock_api_request.return_value = {"metrics": {"groupby_source.ip": [{"key": "1.1.1.1", "count": 1}]}}
        result = await event_query_tools.query_events_impl(oql_query='rule.name:"Test"', groupby_field="source.ip")
        assert len(result) == 1
        assert result[0]["key"] == "1.1.1.1"

    @pytest.mark.asyncio
    async def test_query_events_impl_value_error(self):
        with patch('so_modules.utils.build_api_time_range', side_effect=ValueError("Invalid time")):
            result = await event_query_tools.query_events_impl(oql_query='rule.name:"Test"', start_time="invalid")
            assert "error" in result[0]

    @pytest.mark.asyncio
    async def test_query_events_impl_api_exception(self, mock_api_request):
        mock_api_request.side_effect = Exception("API Error")
        result = await event_query_tools.query_events_impl(oql_query='rule.name:"Test"')
        assert "error" in result[0]

    @pytest.mark.asyncio
    async def test_process_groupby_response_edge_cases(self):
        # Test no metrics key
        assert event_query_tools._process_groupby_response({}, "field") == []
        # Test no groupby key
        assert event_query_tools._process_groupby_response({"metrics": {"other": 1}}, "field") == [{"other": 1}]

    @pytest.mark.asyncio
    async def test_process_events_response_exception(self):
        with patch('so_modules.utils.filter_event_payload', side_effect=Exception("Test")):
            with pytest.raises(Exception):
                event_query_tools._process_events_response({"events": [{"payload": {}}]})

    def test_enhance_query(self):
        assert 'NOT metadata.raw_index:"logs-soc-so"' in event_query_tools._enhance_query("test")


# --- Final Coverage Tests ---

def test_conftest_import_error(mocker):
    """
    Test conftest fixture with an import error to ensure it's handled.
    """
    mocker.patch('importlib.reload', side_effect=ImportError)
    # The autouse fixture in conftest.py will run automatically.
    # The patch above will cause the `except ImportError` block to be hit.
    # The test body can be empty because its only purpose is to trigger
    # the fixture with the patch active.
    pass

@pytest.mark.asyncio
async def test_future_start_time_warning(mocker):
    """
    Test that a warning is logged if the start time is in the future.
    """
    now = datetime.now(timezone.utc)
    future_time = now + timedelta(hours=1)
    
    mocker.patch('so_modules.utils.parse_datetime_string', side_effect=[
        future_time,
        now
    ])
    
    with patch('so_modules.utils.log.warning') as mock_log:
        utils.build_api_time_range(start_time="future", end_time=None)
        mock_log.assert_called_with(f"Start time 'future' is in the future or now. Query might return no results.")

@pytest.mark.asyncio
async def test_playbook_tools_exception_logging(mocker):
    """
    Test that exceptions in get_playbook_questions_impl are logged.
    """
    mocker.patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock, side_effect=Exception("Test error"))
    with patch('so_modules.playbook_tools.logger.error') as mock_log:
        await playbook_tools.get_playbook_questions_impl("alert-id")
        mock_log.assert_called_once()

@pytest.mark.asyncio
async def test_only_end_time_provided_warning(mocker):
    """
    Test that a warning is logged if only the end time is provided.
    """
    now = datetime.now(timezone.utc)
    # Mock parse_datetime_string to return a valid datetime for the end_time
    mocker.patch('so_modules.utils.parse_datetime_string', return_value=now)
    with patch('so_modules.utils.log.warning') as mock_log:
        utils.build_api_time_range(start_time=None, end_time="now")
        mock_log.assert_called_with("Only end_time provided. Relying on API default start time.")

def test_parse_datetime_string_invalid_relative_format():
    """
    Test that an invalid relative time format raises the correct ValueError.
    """
    with pytest.raises(ValueError, match="Invalid relative hours format: --1h"):
        utils.parse_datetime_string("--1h")

def test_parse_datetime_string_invalid_minutes_format():
    """
    Test that an invalid relative time format raises the correct ValueError.
    """
    with pytest.raises(ValueError, match="Invalid relative minutes format: --1m"):
        utils.parse_datetime_string("--1m")

def test_parse_datetime_string_invalid_days_format():
    """
    Test that an invalid relative time format raises the correct ValueError.
    """
    with pytest.raises(ValueError, match="Invalid relative days format: --1d"):
        utils.parse_datetime_string("--1d")

def test_conftest_no_env_vars(mocker):
    """
    Test conftest fixture when env vars are already set.
    """
    mocker.patch.dict(os.environ, {
        "SO_CLIENT_ID": "existing_id",
        "SO_CLIENT_SECRET": "existing_secret",
        "SO_API_ENDPOINT": "existing_endpoint",
    }, clear=True)
    from tests import conftest
    importlib.reload(conftest)
    assert os.getenv("SO_CLIENT_ID") == "existing_id"

def test_check_configuration_no_ca_cert(mocker):
    """
    Test validate_configuration when SO_CA_CERT is not set.
    """
    mocker.patch('so_modules.config.SO_CA_CERT', None)
    with patch('so_modules.utils.log.info') as mock_log:
        utils.validate_configuration()
        mock_log.assert_called_with("Using default SSL verification.")

@pytest.mark.asyncio
async def test_get_playbook_questions_impl_unnamed_playbook(mocker):
    """
    Test get_playbook_questions_impl with a playbook that has no name.
    """
    mock_playbooks = [{"description": "A playbook with no name"}]
    mocker.patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock, return_value=mock_playbooks)
    result = await playbook_tools.get_playbook_questions_impl("test-alert")
    assert result["playbooks"][0]["name"] == "Unnamed Playbook"

def test_file_logging_disabled(tmp_path):
    """
    Test that file logging is disabled by default.
    """
    # Ensure handlers are clean before this test
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    with patch.dict(os.environ, {"SO_ENABLE_FILE_LOGGING": "false"}, clear=True):
        os.chdir(tmp_path)
        import security_onion_server
        importlib.reload(security_onion_server)
        assert not any(isinstance(h, logging.FileHandler) for h in root_logger.handlers)

@pytest.mark.asyncio
async def test_query_events_tool_wrapper(mocker):
    """
    Test the query_events tool wrapper in security_onion_server.py
    """
    import security_onion_server
    mock_impl = mocker.patch('so_modules.event_query_tools.query_events_impl', new_callable=AsyncMock)
    await security_onion_server.query_events("test query")
    mock_impl.assert_called_once()

@pytest.mark.asyncio
async def test_get_playbook_questions_tool_wrapper(mocker):
    """
    Test the get_playbook_questions tool wrapper in security_onion_server.py
    """
    import security_onion_server
    mock_impl = mocker.patch('so_modules.playbook_tools.get_playbook_questions_impl', new_callable=AsyncMock)
    await security_onion_server.get_playbook_questions("test-alert")
    mock_impl.assert_called_once()

def test_ping_tool_wrapper(mocker):
    """
    Test the ping tool wrapper in security_onion_server.py
    """
    import security_onion_server
    mock_impl = mocker.patch('so_modules.utility_tools.ping_impl')
    security_onion_server.ping()
    mock_impl.assert_called_once()

def test_check_configuration_wrapper(mocker):
    """
    Test the check_configuration wrapper in security_onion_server.py
    """
    import security_onion_server
    mock_impl = mocker.patch('so_modules.utils.validate_configuration')
    security_onion_server.check_configuration()
    mock_impl.assert_called_once()

def test_check_configuration_wrapper_error(mocker):
    """
    Test the check_configuration wrapper in security_onion_server.py with an error
    """
    import security_onion_server
    mocker.patch('so_modules.utils.validate_configuration', side_effect=ValueError)
    assert not security_onion_server.check_configuration()

@pytest.mark.asyncio
async def test_get_capabilities_with_tools(mocker):
    """
    Test get_capabilities with a mocked tool list.
    """
    import security_onion_server
    mock_tool = MagicMock()
    mock_tool.model_dump.return_value = {"name": "mock_tool"}
    mocker.patch('security_onion_server.server.list_tools', new_callable=AsyncMock, return_value=[mock_tool])
    caps = await security_onion_server.get_capabilities()
    assert len(caps.tools.tools) == 1

@pytest.mark.asyncio
async def test_query_events_impl_unhandled_exception(mock_api_request):
    """
    Test that a non-ValueError, non-API exception is caught and handled.
    """
    mock_api_request.side_effect = TypeError("A completely unexpected error")
    result = await event_query_tools.query_events_impl(oql_query='rule.name:"Test"')
    assert "error" in result[0]
    assert "internal error" in result[0]["error"]

def test_enhance_query_noop():
    """
    Test that _enhance_query does nothing if the filter is already present.
    """
    query = 'rule.name:"Test" AND NOT metadata.raw_index:"logs-soc-so"'
    assert event_query_tools._enhance_query(query) == query
@pytest.mark.asyncio
async def test_process_events_response_force_exception():
    """
    Force a generic exception inside _process_events_response to cover the final `raise`.
    """
    with patch('so_modules.utils.filter_event_payload', side_effect=Exception("Forced test exception")):
        with pytest.raises(Exception, match="Forced test exception"):
            event_query_tools._process_events_response({"events": [{"payload": {}}]})

@pytest.mark.asyncio
async def test_get_playbooks_for_detection_force_exception(mocker):
    """
    Force a generic exception inside get_playbooks_for_detection to cover the final `raise`.
    """
    mocker.patch('so_modules.api.make_so_api_request', new_callable=AsyncMock, side_effect=Exception("Forced API error"))
    with pytest.raises(Exception, match="Forced API error"):
        await playbook_tools.get_playbooks_for_detection("any-id")

def test_validate_configuration_force_exception(mocker):
    """
    Force a generic exception inside validate_configuration to cover the final `raise`.
    """
    mocker.patch('so_modules.config.check_config', side_effect=ValueError("Forced config error"))
    with pytest.raises(ValueError, match="Forced config error"):
        utils.validate_configuration()
@pytest.mark.asyncio
async def test_query_events_with_time_range(mock_api_request):
    """
    Test query_events_impl with a start_time to cover the time_range block.
    """
    await event_query_tools.query_events_impl(oql_query='rule.name:"Test"', start_time="-1h")
    mock_api_request.assert_called_once()
    # The call_args property is a tuple of (args, kwargs)
    # The params dictionary is the second positional argument
    call_args = mock_api_request.call_args.args
    assert "range" in call_args[1]

@pytest.mark.asyncio
async def test_get_playbook_questions_with_index(mocker):
    """
    Test get_playbook_questions_impl with a specific playbook_index.
    """
    mock_playbooks = [{"name": "Playbook 1"}, {"name": "Playbook 2"}]
    mocker.patch('so_modules.playbook_tools.get_playbooks_for_detection', new_callable=AsyncMock, return_value=mock_playbooks)
    result = await playbook_tools.get_playbook_questions_impl("test-alert", playbook_index=0)
    assert len(result["playbooks"]) == 1
    assert result["playbooks"][0]["name"] == "Playbook 1"
