"""
CTF Environment Client.

Provides the client for connecting to a CTF Environment server.
CtfEnv extends MCPToolClient to provide tool-calling style interactions.

Example:
    >>> with CtfEnv(base_url="http://localhost:8000") as env:
    ...     env.reset(task="sqli_login")
    ...     tools = env.list_tools()
    ...     result = env.call_tool("view_source", file_path="routes/auth.py")
    ...     result = env.call_tool("http_request", method="POST", path="/login",
    ...                            body={"username": "' OR 1=1 --", "password": "x"})
    ...     result = env.call_tool("submit_flag", flag="FLAG{...}")
"""

from openenv.core.mcp_client import MCPToolClient


class CtfEnv(MCPToolClient):
    """
    Client for the CTF Vulnerability Discovery Environment.

    Inherits all functionality from MCPToolClient:
    - list_tools(): Discover available tools
    - call_tool(name, **kwargs): Call a tool by name
    - reset(**kwargs): Reset the environment (pass task= to select challenge)
    - step(action): Execute an action (for advanced use)
    """

    pass
