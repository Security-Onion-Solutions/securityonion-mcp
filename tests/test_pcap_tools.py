# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""Tests for PCAP retrieval tools."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from so_modules import pcap_tools


class TestGetPcap:
    """Test cases for the get_pcap function."""
    
    @pytest.mark.asyncio
    async def test_get_pcap_by_community_id(self):
        """Test retrieving PCAP by community ID."""
        mock_response = {
            "data": "base64encodedpcapdata==",
            "size": 1024,
            "packet_count": 10,
            "first_packet_time": "2024-12-20T10:00:00Z",
            "last_packet_time": "2024-12-20T10:01:00Z"
        }
        
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_response
            
            result = await pcap_tools.get_pcap(
                community_id="1:bzmeJDGMrYGddwMIFvT900znyP4="
            )
            
            # Verify API was called with correct parameters
            mock_api.assert_called_once()
            call_args = mock_api.call_args
            assert call_args[0][0] == "/connect/pcap"
            assert "query" in call_args[0][1]
            assert "network.community_id:1:bzmeJDGMrYGddwMIFvT900znyP4=" in call_args[0][1]["query"]
            
            # Verify response structure
            assert "pcap_data" in result
            assert result["pcap_data"] == "base64encodedpcapdata=="
            assert "metadata" in result
            assert result["metadata"]["size_bytes"] == 1024
            assert result["metadata"]["packet_count"] == 10
    
    @pytest.mark.asyncio
    async def test_get_pcap_by_ip_and_time(self):
        """Test retrieving PCAP by IP addresses and time range."""
        mock_response = {
            "data": "base64encodedpcapdata==",
            "size": 2048,
            "packet_count": 20
        }
        
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_response
            
            result = await pcap_tools.get_pcap(
                source_ip="192.168.1.100",
                destination_ip="10.0.0.50",
                start_time="-1h",
                end_time="now"
            )
            
            # Verify API was called
            mock_api.assert_called_once()
            call_args = mock_api.call_args
            assert "source.ip:192.168.1.100" in call_args[0][1]["query"]
            assert "destination.ip:10.0.0.50" in call_args[0][1]["query"]
            assert "beginTime" in call_args[0][1]
            assert "endTime" in call_args[0][1]
    
    @pytest.mark.asyncio
    async def test_get_pcap_by_ports(self):
        """Test retrieving PCAP by port numbers."""
        mock_response = {"data": "base64data==", "size": 512, "packet_count": 5}
        
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_response
            
            result = await pcap_tools.get_pcap(
                source_port=443,
                destination_port=8080
            )
            
            # Verify port filters in query
            call_args = mock_api.call_args
            assert "source.port:443" in call_args[0][1]["query"]
            assert "destination.port:8080" in call_args[0][1]["query"]
    
    @pytest.mark.asyncio
    async def test_get_pcap_by_event_id(self):
        """Test retrieving PCAP by event ID."""
        mock_response = {"data": "base64data==", "size": 1024, "packet_count": 8}
        
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_response
            
            result = await pcap_tools.get_pcap(event_id="CqZD628KKcY7ASZjj")
            
            # Verify event ID in query
            call_args = mock_api.call_args
            assert "log.id.uid:CqZD628KKcY7ASZjj" in call_args[0][1]["query"]
    
    @pytest.mark.asyncio
    async def test_get_pcap_no_criteria_error(self):
        """Test error when no search criteria provided."""
        result = await pcap_tools.get_pcap()
        
        assert "error" in result
        assert "At least one search criteria must be provided" in result["error"]
    
    @pytest.mark.asyncio
    async def test_get_pcap_invalid_format(self):
        """Test error for invalid output format."""
        result = await pcap_tools.get_pcap(
            community_id="1:test",
            format="invalid"
        )
        
        assert "error" in result
        assert "Invalid format: invalid" in result["error"]
    
    @pytest.mark.asyncio
    async def test_get_pcap_file_format_not_implemented(self):
        """Test that file format returns not implemented error."""
        result = await pcap_tools.get_pcap(
            community_id="1:test",
            format="file"
        )
        
        assert "error" in result
        assert "File format not yet implemented" in result["error"]
    
    @pytest.mark.asyncio
    async def test_get_pcap_api_error(self):
        """Test handling of API errors."""
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.side_effect = Exception("API connection failed")
            
            result = await pcap_tools.get_pcap(community_id="1:test")
            
            assert "error" in result
            assert "Failed to retrieve PCAP" in result["error"]
            assert "API connection failed" in result["details"]
    
    @pytest.mark.asyncio
    async def test_get_pcap_multiple_filters(self):
        """Test combining multiple search filters."""
        mock_response = {"data": "base64data==", "size": 4096, "packet_count": 50}
        
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_response
            
            result = await pcap_tools.get_pcap(
                community_id="1:test",
                source_ip="192.168.1.100",
                destination_port=443,
                start_time="-30m"
            )
            
            # Verify all filters are combined with AND
            call_args = mock_api.call_args
            query = call_args[0][1]["query"]
            assert "network.community_id:1:test" in query
            assert "source.ip:192.168.1.100" in query
            assert "destination.port:443" in query
            assert " AND " in query


class TestGetPcapMetadata:
    """Test cases for the get_pcap_metadata function."""
    
    @pytest.mark.asyncio
    async def test_get_pcap_metadata_success(self):
        """Test successful PCAP metadata retrieval."""
        mock_response = {
            "available": True,
            "size": 10240,
            "packet_count": 100,
            "sensors": ["sensor1", "sensor2"],
            "time_range": {
                "start": "2024-12-20T10:00:00Z",
                "end": "2024-12-20T10:10:00Z"
            }
        }
        
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_response
            
            result = await pcap_tools.get_pcap_metadata(
                community_id="1:test",
                start_time="-1h"
            )
            
            # Verify API call
            mock_api.assert_called_once()
            call_args = mock_api.call_args
            assert call_args[0][0] == "/connect/pcap/metadata"
            assert call_args[0][1]["metadata_only"] == "true"
            assert "query" in call_args[0][1]
            
            # Verify response
            assert result["available"] is True
            assert result["size_bytes"] == 10240
            assert result["packet_count"] == 100
            assert len(result["sensors"]) == 2
    
    @pytest.mark.asyncio
    async def test_get_pcap_metadata_not_available(self):
        """Test metadata when PCAP is not available."""
        mock_response = {
            "available": False,
            "size": 0,
            "packet_count": 0,
            "sensors": [],
            "time_range": {}
        }
        
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.return_value = mock_response
            
            result = await pcap_tools.get_pcap_metadata(community_id="1:notfound")
            
            assert result["available"] is False
            assert result["size_bytes"] == 0
            assert result["packet_count"] == 0
    
    @pytest.mark.asyncio
    async def test_get_pcap_metadata_error(self):
        """Test metadata retrieval error handling."""
        with patch('so_modules.pcap_tools.make_so_api_request', new_callable=AsyncMock) as mock_api:
            mock_api.side_effect = Exception("Metadata API error")
            
            result = await pcap_tools.get_pcap_metadata(community_id="1:test")
            
            assert "error" in result
            assert "Failed to retrieve PCAP metadata" in result["error"]
            assert "Metadata API error" in result["details"]