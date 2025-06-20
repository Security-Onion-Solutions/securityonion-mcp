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
from so_modules import api, config, event_query_tools, utility_tools, utils, playbook_tools, alert_tools, pcap_tools
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
        utils.validate_configuration()
        return True
    except ValueError:
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


@server.tool()
async def get_playbook_questions(
    alert_id: str,
    playbook_index: typing.Optional[int] = None
) -> dict:
    """
    Get playbook questions for a given alert/detection to guide investigation.
    
    When an alert is triggered, playbooks provide guided questions to help investigate
    the incident. This tool retrieves the playbook questions without executing queries,
    allowing you to build appropriate queries based on the questions and available data.
    
    Args:
        alert_id: The alert/detection ID (event.id or rule.uuid)
        playbook_index: Optional index to get questions from a specific playbook (0-based).
                        If not provided, questions from all playbooks are returned.
    
    Returns:
        Dictionary containing:
        - alert_id: The provided alert ID
        - playbooks: List of playbooks, each containing:
          - name: Playbook name
          - description: Playbook description
          - questions: List of questions with:
            - question: The investigation question
            - context: Why this question is important
            - answer_sources: Where to find answers
            - suggested_query: A template query (may contain variables)
            - time_range: Suggested time range for the query
        - error: Error message if retrieval failed
    
    Example:
        # Get all playbook questions for an alert
        questions = await get_playbook_questions("6F64990A-ACDA-40B6-AB71-134C073013B5")
        
        # Get questions from only the first playbook
        questions = await get_playbook_questions("alert-123", playbook_index=0)
        
        # Then use the questions to build appropriate OQL queries
    """
    return await playbook_tools.get_playbook_questions_impl(
        alert_id=alert_id,
        playbook_index=playbook_index
    )


@server.tool()
async def acknowledge_alerts(
    acknowledge: bool = True,
    search_filter: typing.Optional[str] = None,
    event_filter: typing.Optional[typing.Dict[str, str]] = None,
    date_range: typing.Optional[str] = None,
    date_range_format: typing.Optional[str] = None,
    timezone: typing.Optional[str] = None,
    escalate: typing.Optional[bool] = None
) -> typing.Dict[str, typing.Any]:
    """
    Acknowledge or unacknowledge alert events matching the given criteria.
    
    This tool allows you to mark alerts as acknowledged (reviewed) or unacknowledged.
    Acknowledged alerts will not appear on users' Alert screens after refresh.
    
    Args:
        acknowledge: Whether to acknowledge (True) or unacknowledge (False) the events.
        search_filter: OQL search filter to find matching events (e.g., "tags:alert AND rule.uuid:xyz").
        event_filter: Optional dict of field:value pairs to further filter events (e.g., {"rule.name": "Suspicious Login"}).
        date_range: Date range for searching events (e.g., "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM").
        date_range_format: Format of the date range (default: "2006/01/02 3:04:05 PM").
        timezone: Timezone for date range (default: "America/New_York").
        escalate: Whether events have been escalated to a case.
    
    Returns:
        Dictionary containing update results including:
        - updated: Number of events updated
        - failed: Number of events that failed to update
        - errors: List of any errors encountered
        - completeTime: When the operation completed
        - elapsedMs: How long the operation took
    
    Examples:
        # Acknowledge all unacknowledged alerts from a specific rule
        await acknowledge_alerts(
            acknowledge=True,
            search_filter="tags:alert AND NOT event.acknowledged:true AND rule.uuid:bf86ef21-41e6-417b-9a05-b9ea6bf28a38"
        )
        
        # Acknowledge alerts with specific criteria
        await acknowledge_alerts(
            acknowledge=True,
            search_filter="tags:alert AND NOT event.acknowledged:true",
            event_filter={"rule.name": "Security Onion - SOC Login Failure", "event.module": "sigma"}
        )
        
        # Unacknowledge previously acknowledged alerts
        await acknowledge_alerts(
            acknowledge=False,
            search_filter="tags:alert AND event.acknowledged:true",
            date_range="2024/12/01 00:00:00 AM - 2024/12/04 11:59:59 PM"
        )
    """
    return await alert_tools.acknowledge_alerts_impl(
        acknowledge=acknowledge,
        search_filter=search_filter,
        event_filter=event_filter,
        date_range=date_range,
        date_range_format=date_range_format,
        timezone=timezone,
        escalate=escalate
    )


@server.tool()
async def get_pcap(
    community_id: typing.Optional[str] = None,
    start_time: typing.Optional[str] = None,
    end_time: typing.Optional[str] = None,
    source_ip: typing.Optional[str] = None,
    destination_ip: typing.Optional[str] = None,
    source_port: typing.Optional[int] = None,
    destination_port: typing.Optional[int] = None,
    event_id: typing.Optional[str] = None,
    format: str = "base64"
) -> typing.Dict[str, typing.Any]:
    """
    Retrieve PCAP data from Security Onion based on various search criteria.
    
    This tool allows you to download packet capture (PCAP) data for specific network
    connections or events. You must provide at least one search criteria.
    
    Args:
        community_id: The network community ID to retrieve PCAP for (e.g., "1:bzmeJDGMrYGddwMIFvT900znyP4=")
        start_time: Start time for PCAP search (e.g., "-1h", "2024/12/20 10:00:00 AM")
        end_time: End time for PCAP search (e.g., "now", "2024/12/20 11:00:00 AM")
        source_ip: Filter by source IP address
        destination_ip: Filter by destination IP address
        source_port: Filter by source port number
        destination_port: Filter by destination port number
        event_id: Specific event ID (log.id.uid) to get PCAP for
        format: Output format - "base64" (default) or "file"
    
    Returns:
        Dictionary containing:
        - pcap_data: Base64 encoded PCAP data (if format is base64)
        - metadata: Information about the PCAP (size, packet count, time range)
        - error: Error message if retrieval failed
    
    Examples:
        # Get PCAP by community ID (from a connection or alert)
        await get_pcap(community_id="1:bzmeJDGMrYGddwMIFvT900znyP4=")
        
        # Get PCAP for specific IP communication in the last hour
        await get_pcap(
            source_ip="192.168.1.100",
            destination_ip="10.0.0.50",
            start_time="-1h",
            end_time="now"
        )
        
        # Get PCAP for a specific event
        await get_pcap(event_id="CqZD628KKcY7ASZjj")
    """
    return await pcap_tools.get_pcap(
        community_id=community_id,
        start_time=start_time,
        end_time=end_time,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        event_id=event_id,
        format=format
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
