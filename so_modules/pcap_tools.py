# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
PCAP retrieval tools for Security Onion MCP.

This module provides functionality to retrieve PCAP data from Security Onion
based on various identifiers like community ID, time ranges, or specific IPs.
"""

import base64
import logging
from typing import Optional, Dict, Any

from .api import make_so_api_request
from .utils import parse_datetime_string

logger = logging.getLogger(__name__)


async def get_pcap(
    community_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    event_id: Optional[str] = None,
    format: str = "base64"
) -> Dict[str, Any]:
    """
    Retrieve PCAP data from Security Onion based on various search criteria.
    
    Args:
        community_id: The network community ID to retrieve PCAP for
        start_time: Start time for PCAP search (e.g., "-1h", "2024-12-20 10:00:00")
        end_time: End time for PCAP search (e.g., "now", "2024-12-20 11:00:00")
        source_ip: Filter by source IP address
        destination_ip: Filter by destination IP address
        source_port: Filter by source port
        destination_port: Filter by destination port
        event_id: Specific event ID to get PCAP for
        format: Output format - "base64" (default) or "file"
    
    Returns:
        Dictionary containing:
        - pcap_data: Base64 encoded PCAP data (if format is base64)
        - file_path: Path to downloaded PCAP file (if format is file)
        - metadata: Information about the PCAP (size, packet count, etc.)
        - error: Error message if retrieval failed
    
    Example:
        # Get PCAP by community ID
        pcap = await get_pcap(community_id="1:bzmeJDGMrYGddwMIFvT900znyP4=")
        
        # Get PCAP by IP and time range
        pcap = await get_pcap(
            source_ip="192.168.1.100",
            start_time="-1h",
            end_time="now"
        )
    """
    try:
        # Validate format first
        if format not in ["base64", "file"]:
            return {
                "error": f"Invalid format: {format}",
                "details": "Supported formats: base64, file"
            }
        
        if format == "file":
            return {
                "error": "File format not yet implemented",
                "details": "Currently only base64 format is supported"
            }
        
        # Build the query parameters
        params = {}
        
        # Add time range if specified
        if start_time:
            parsed_start = parse_datetime_string(start_time)
            params["beginTime"] = parsed_start.strftime("%Y/%m/%d %I:%M:%S %p")
        
        if end_time:
            parsed_end = parse_datetime_string(end_time)
            params["endTime"] = parsed_end.strftime("%Y/%m/%d %I:%M:%S %p")
        
        # Build the search filter
        filters = []
        
        if community_id:
            filters.append(f"network.community_id:{community_id}")
        
        if source_ip:
            filters.append(f"source.ip:{source_ip}")
            
        if destination_ip:
            filters.append(f"destination.ip:{destination_ip}")
            
        if source_port:
            filters.append(f"source.port:{source_port}")
            
        if destination_port:
            filters.append(f"destination.port:{destination_port}")
            
        if event_id:
            filters.append(f"log.id.uid:{event_id}")
        
        # If no filters provided, return error
        if not filters:
            return {
                "error": "At least one search criteria must be provided",
                "details": "Specify community_id, event_id, IP addresses, or ports"
            }
        
        # Combine filters with AND
        query = " AND ".join(filters)
        params["query"] = query
        
        # Make the API request to the PCAP endpoint
        # Note: The actual endpoint path may vary - this is a common pattern
        response = await make_so_api_request("/connect/pcap", params)
        
        # Return base64 encoded PCAP data
        return {
            "pcap_data": response.get("data", ""),
            "metadata": {
                "size_bytes": response.get("size", 0),
                "packet_count": response.get("packet_count", 0),
                "time_range": {
                    "start": response.get("first_packet_time"),
                    "end": response.get("last_packet_time")
                }
            }
        }
            
    except Exception as e:
        logger.error(f"Failed to retrieve PCAP: {str(e)}")
        return {
            "error": "Failed to retrieve PCAP",
            "details": str(e)
        }


async def get_pcap_metadata(
    community_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get metadata about available PCAP data without downloading it.
    
    This is useful for checking if PCAP data exists and understanding
    its size before downloading.
    
    Args:
        community_id: The network community ID
        start_time: Start time for search
        end_time: End time for search
    
    Returns:
        Dictionary containing PCAP metadata
    """
    try:
        params = {
            "metadata_only": "true"
        }
        
        if community_id:
            params["query"] = f"network.community_id:{community_id}"
            
        if start_time:
            params["beginTime"] = parse_datetime_string(start_time).strftime("%Y/%m/%d %I:%M:%S %p")
            
        if end_time:
            params["endTime"] = parse_datetime_string(end_time).strftime("%Y/%m/%d %I:%M:%S %p")
        
        response = await make_so_api_request("/connect/pcap/metadata", params)
        
        return {
            "available": response.get("available", False),
            "size_bytes": response.get("size", 0),
            "packet_count": response.get("packet_count", 0),
            "sensors": response.get("sensors", []),
            "time_range": response.get("time_range", {})
        }
        
    except Exception as e:
        logger.error(f"Failed to retrieve PCAP metadata: {str(e)}")
        return {
            "error": "Failed to retrieve PCAP metadata",
            "details": str(e)
        }