"""
FastAPI application for the CTF Vulnerability Discovery Environment.

This module creates an HTTP server that exposes the CTFEnvironment
over HTTP and WebSocket endpoints, compatible with MCPToolClient.

Usage:
    # Development:
    uvicorn server.app:app --reload --host 0.0.0.0 --port 8000

    # Production:
    uvicorn server.app:app --host 0.0.0.0 --port 8000
"""

from openenv.core.env_server.http_server import create_app
from openenv.core.env_server.mcp_types import CallToolAction, CallToolObservation

try:
    from .ctf_environment import CTFEnvironment
except ImportError:
    from server.ctf_environment import CTFEnvironment

# Create the app with the CTFEnvironment class (factory pattern)
app = create_app(
    CTFEnvironment,
    CallToolAction,
    CallToolObservation,
    env_name="ctf_env",
)


def main():
    """
    Entry point for direct execution.

    Enables running:
        uv run --project . server
        python -m server.app
    """
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
