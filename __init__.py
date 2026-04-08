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
    ...     result = env.call_tool("view_source", file_path="src/routes/auth.js")
    ...     print(result)
"""

from .client import CtfEnv

# Lazy imports — only load server-side types when explicitly needed,
# avoids pulling in gradio/env_server for client-only usage (inference.py)
def __getattr__(name):
    if name == "CallToolAction":
        from openenv.core.env_server.mcp_types import CallToolAction
        return CallToolAction
    if name == "ListToolsAction":
        from openenv.core.env_server.mcp_types import ListToolsAction
        return ListToolsAction
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["CtfEnv", "CallToolAction", "ListToolsAction"]
