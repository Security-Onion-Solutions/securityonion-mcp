# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

from mcp.server.fastmcp import FastMCP
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types
import asyncio
import logging
import typing # Need this for Optional
from so_modules import api, config, event_query_tools, utility_tools, utils # Removed rule_tools import
# Configure basic logging (console), setting level to WARNING to suppress DEBUG/INFO
# This also configures the root logger initially.
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Get the root logger
root_logger = logging.getLogger()

# Get a logger for the current module
log = logging.getLogger(__name__)

# Check if file logging should be enabled (disabled by default)
import os
enable_file_logging = os.getenv("SO_ENABLE_FILE_LOGGING", "false").lower() in ("true", "1", "yes")

if enable_file_logging:
    # Create a file handler to log to securityonion-mcp.log
    log_file = "securityonion-mcp.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)  # Log INFO level and above to the file
    
    # Create a formatter and set it for the file handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Add the file handler to the root logger
    root_logger.addHandler(file_handler)
    log.info(f"File logging configured to: {log_file}")
else:
    log.debug("File logging is disabled. Set SO_ENABLE_FILE_LOGGING=true to enable.")

# Initialize the server
server = FastMCP("Security Onion MCP")

def check_configuration():
    """Check if the required configuration is set."""
    try:
        config.check_config()
        return True
    except ValueError as e:
        log.critical(f"Configuration error: {e}")
        return False


async def get_capabilities():
    """
    Gets the server capabilities.
    """
    tools = await server.list_tools()
    return types.ServerCapabilities(
        tools=types.ToolsCapability(tools=[tool.model_dump(exclude_none=True) for tool in tools]),
        resourceTemplates=[],
        prompts=types.PromptsCapability(),
    )


@server.tool()
def ping() -> str:
    """
    Simple tool to check if the server is running.
    """
    return utility_tools.ping_impl()

@server.tool()
async def query_events(
    oql_query: str,
    start_time: typing.Optional[str] = None,
    end_time: typing.Optional[str] = None,
    limit: int = 100,
    groupby_field: typing.Optional[str] = None
) -> list[dict]:
    """
    Executes a specific OQL query against the Security Onion event dataset.
    
    Args:
        oql_query: The OQL query string to execute.
        start_time: Optional start time for the query range (e.g., "-1h", "2023-10-26 10:00:00").
        end_time: Optional end time for the query range (e.g., "now", "2023-10-26 12:00:00").
        limit: The maximum number of events to return (default: 100).
        groupby_field: Optional OQL field name to group results by.
    Returns:
        A list of event dictionaries matching the query with filtered payloads.
    """
    return await event_query_tools.query_events_impl(
        oql_query=oql_query,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        groupby_field=groupby_field
    )

async def run():
    """Run the server if configuration is valid."""
    if not check_configuration():
        # Exit or prevent server start if config is invalid
        if __name__ == "__main__":
            exit(1)
        return
    
    await server.run_stdio_async()


if __name__ == "__main__":
    asyncio.run(run())  # pragma: no cover
