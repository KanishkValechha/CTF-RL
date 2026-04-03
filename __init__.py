"""
CTF Vulnerability Discovery Environment for OpenEnv.

An AI security researcher sandbox where agents discover and exploit
web application vulnerabilities across three difficulty levels:
- Easy: SQL Injection in a login form
- Medium: IDOR + Privilege Escalation to access admin panel
- Hard: Business logic vulnerability in a payment flow

Example:
    >>> from ctf_env import CtfEnv
    >>>
    >>> with CtfEnv(base_url="http://localhost:8000") as env:
    ...     env.reset(task="sqli_login")
    ...     tools = env.list_tools()
    ...     result = env.call_tool("view_source", file_path="routes/auth.py")
    ...     print(result)
"""

from openenv.core.env_server.mcp_types import CallToolAction, ListToolsAction

from .client import CtfEnv

__all__ = ["CtfEnv", "CallToolAction", "ListToolsAction"]
