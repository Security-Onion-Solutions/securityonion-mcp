# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Playbook tools for Security Onion MCP server.
Returns playbook questions without executing queries, allowing LLMs to build appropriate queries.
"""

import logging
from typing import Dict, List, Any, Optional

from . import api

logger = logging.getLogger(__name__)


async def get_playbooks_for_detection(detection_id: str) -> List[Dict[str, Any]]:
    """
    Fetch playbooks associated with a specific detection/alert ID.
    
    Args:
        detection_id: The public ID of the detection/alert
        
    Returns:
        List of playbook dictionaries
    """
    endpoint = f"/connect/playbook/detection/{detection_id}"
    
    try:
        # make_so_api_request doesn't take a method parameter, it's always GET
        response = await api.make_so_api_request(endpoint, params={})
        return response if isinstance(response, list) else []
    except Exception as e:
        logger.error(f"Failed to fetch playbooks for detection {detection_id}: {e}")
        raise


async def get_playbook_questions_impl(
    alert_id: str,
    playbook_index: Optional[int] = None
) -> Dict[str, Any]:
    """
    Get playbook questions for a given alert without executing queries.
    
    Args:
        alert_id: The alert/detection ID
        playbook_index: Optional index to get questions from a specific playbook (0-based)
        
    Returns:
        Dictionary containing playbook questions and metadata
    """
    try:
        # Fetch playbooks for the detection
        playbooks = await get_playbooks_for_detection(alert_id)
        
        if not playbooks:
            return {
                "alert_id": alert_id,
                "error": "No playbooks found for this detection",
                "playbooks": []
            }
        
        # If specific playbook requested, validate index
        if playbook_index is not None:
            if playbook_index < 0 or playbook_index >= len(playbooks):
                return {
                    "alert_id": alert_id,
                    "error": f"Invalid playbook index. Found {len(playbooks)} playbooks.",
                    "playbooks": []
                }
            playbooks = [playbooks[playbook_index]]
        
        # Format the response with questions
        results = {
            "alert_id": alert_id,
            "playbooks": []
        }
        
        for playbook in playbooks:
            playbook_result = {
                "name": playbook.get("name", "Unnamed Playbook"),
                "description": playbook.get("description", ""),
                "questions": []
            }
            
            # Extract questions without executing queries
            questions = playbook.get("questions", [])
            for question in questions:
                question_data = {
                    "question": question.get("question", ""),
                    "context": question.get("context", ""),
                    "answer_sources": question.get("answer_sources", []),
                    "suggested_query": question.get("query", ""),
                    "time_range": question.get("range", "+/-1h")
                }
                playbook_result["questions"].append(question_data)
            
            results["playbooks"].append(playbook_result)
        
        return results
        
    except Exception as e:
        logger.error(f"Failed to get playbook questions: {e}")
        return {
            "alert_id": alert_id,
            "error": str(e),
            "playbooks": []
        }