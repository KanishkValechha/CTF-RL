"""
Data models for the CTF Environment.

This environment primarily uses MCP actions (tools/call) which have their own
schemas defined dynamically via FastMCP. This file is required by OpenEnv
strict validation.
"""
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Fallback error response model."""
    error: str
    details: Optional[Dict[str, Any]] = None
