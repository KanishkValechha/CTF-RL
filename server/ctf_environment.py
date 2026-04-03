"""
CTF Vulnerability Discovery Environment.

The core environment class that integrates the vulnerable Flask app,
MCP tools, task management, and reward tracking into an OpenEnv-compatible
MCPEnvironment.
"""

import os
import json
import threading
import tempfile
from typing import Any, Optional
from uuid import uuid4

import requests as http_requests

try:
    from openenv.core.env_server.mcp_environment import MCPEnvironment
    from openenv.core.env_server.types import Action, Observation, State
except ImportError:
    from openenv.core.env_server.mcp_environment import MCPEnvironment
    from openenv.core.env_server.types import Action, Observation, State

from fastmcp import FastMCP

from .tasks.base_task import BaseTask
from .tasks.sqli_task import sqli_task
from .tasks.idor_task import idor_task
from .tasks.payment_task import payment_task
from .reward import RewardTracker
from .graders import TaskGrader
from .vulnerable_app.config import MAX_STEPS_PER_EPISODE, FLAGS, VULN_APP_HOST, VULN_APP_PORT


# All available tasks
TASKS: dict[str, BaseTask] = {
    "sqli_login": sqli_task,
    "idor_privesc": idor_task,
    "payment_logic": payment_task,
}

# Source files available for agent viewing (relative to vulnerable_app/routes)
VIEWABLE_SOURCE_FILES = {
    "routes/auth.py": os.path.join(os.path.dirname(__file__), "vulnerable_app", "routes", "auth.py"),
    "routes/users.py": os.path.join(os.path.dirname(__file__), "vulnerable_app", "routes", "users.py"),
    "routes/admin.py": os.path.join(os.path.dirname(__file__), "vulnerable_app", "routes", "admin.py"),
    "routes/payments.py": os.path.join(os.path.dirname(__file__), "vulnerable_app", "routes", "payments.py"),
    "config.py": os.path.join(os.path.dirname(__file__), "vulnerable_app", "config.py"),
    "database.py": os.path.join(os.path.dirname(__file__), "vulnerable_app", "database.py"),
    "app.py": os.path.join(os.path.dirname(__file__), "vulnerable_app", "app.py"),
}


class CTFEnvironment(MCPEnvironment):
    """
    CTF Vulnerability Discovery Environment.

    An AI security researcher sandbox where agents discover and exploit
    web application vulnerabilities. Integrates:
    - A vulnerable Flask application (running in-process on a background thread)
    - MCP tools for agent interaction (view_source, http_request, submit_flag)
    - Milestone-based reward tracking with noise detection
    - Deterministic grading (0.0-1.0)
    """

    def __init__(self):
        """Initialize the CTF environment with MCP tools."""
        mcp = FastMCP("ctf_env")

        # ── Define MCP Tools (self is captured via closure) ──
        env_ref = self

        @mcp.tool
        def list_source_files() -> dict:
            """
            List all source code files available for viewing.

            Use this to discover what files you can read to understand
            the application's code and find vulnerabilities.

            Returns:
                Dictionary with 'files' (list of viewable file paths)
                and 'task_relevant_files' (files most relevant to the current task).
            """
            task = env_ref._active_task
            relevant = task.relevant_files if task else []
            return {
                "files": sorted(VIEWABLE_SOURCE_FILES.keys()),
                "task_relevant_files": relevant,
            }

        @mcp.tool
        def view_source(file_path: str) -> dict:
            """
            View the source code of a file in the vulnerable application.

            Read source code to understand how the application works and
            identify security vulnerabilities.

            Args:
                file_path: Relative path to the source file
                          (e.g., "routes/auth.py", "database.py")

            Returns:
                Dictionary with 'file_path', 'content' (source code),
                and 'lines' (line count).
            """
            abs_path = VIEWABLE_SOURCE_FILES.get(file_path)
            if abs_path is None:
                return {
                    "error": f"File '{file_path}' not found. Use list_source_files() to see available files.",
                    "available_files": sorted(VIEWABLE_SOURCE_FILES.keys()),
                }

            try:
                with open(abs_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    result = {
                        "file_path": file_path,
                        "content": content,
                        "lines": len(content.splitlines()),
                    }
                    # Update reward tracker
                    if env_ref._tracker:
                        env_ref._step_reward = env_ref._tracker.update(
                            "view_source", {"file_path": file_path}, result
                        )
                    return result
            except Exception as e:
                return {"error": f"Failed to read file: {str(e)}"}

        @mcp.tool
        def http_request(
            method: str,
            path: str,
            headers: dict | None = None,
            body: dict | None = None,
            cookies: dict | None = None,
        ) -> dict:
            """
            Send an HTTP request to the vulnerable application.

            Use this to interact with the web application: login, access
            endpoints, send payloads, and test for vulnerabilities.

            Args:
                method: HTTP method (GET, POST, PUT, DELETE)
                path: URL path (e.g., "/login", "/api/users/1")
                headers: Optional HTTP headers dictionary
                body: Optional request body (JSON dictionary)
                cookies: Optional cookies dictionary

            Returns:
                Dictionary with 'status_code', 'headers', 'body',
                and 'cookies' from the response.
            """
            base_url = f"http://{VULN_APP_HOST}:{env_ref._vuln_port}"
            url = f"{base_url}{path}"
            method = method.upper()

            # Merge persistent cookies with provided cookies
            merged_cookies = dict(env_ref._session_cookies)
            if cookies:
                merged_cookies.update(cookies)

            try:
                response = http_requests.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    json=body if method in ("POST", "PUT", "PATCH") else None,
                    params=body if method == "GET" and body else None,
                    cookies=merged_cookies,
                    timeout=10,
                    allow_redirects=False,
                )

                # Persist cookies from response
                if response.cookies:
                    env_ref._session_cookies.update(dict(response.cookies))

                # Parse response body
                try:
                    resp_body = response.json()
                except (ValueError, Exception):
                    resp_body = response.text[:2000]

                result = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": resp_body,
                    "cookies": dict(response.cookies) if response.cookies else {},
                }

                # Update reward tracker
                if env_ref._tracker:
                    action_args = {
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body": body,
                        "cookies": cookies,
                    }
                    env_ref._step_reward = env_ref._tracker.update(
                        "http_request", action_args, result
                    )

                return result

            except http_requests.exceptions.ConnectionError:
                return {
                    "error": "Connection refused. The vulnerable app may not be running.",
                    "status_code": 0,
                }
            except Exception as e:
                return {
                    "error": f"Request failed: {str(e)}",
                    "status_code": 0,
                }

        @mcp.tool
        def submit_flag(flag: str) -> dict:
            """
            Submit a captured flag for verification.

            Use this when you've found the flag through exploitation.
            The flag format is FLAG{...}.

            Args:
                flag: The flag string (e.g., "FLAG{sqli_bypass_auth_2024}")

            Returns:
                Dictionary with 'correct' (bool), 'message',
                'score', and 'grade_summary'.
            """
            task = env_ref._active_task
            if task is None:
                return {"error": "No active task. Call reset() first.", "correct": False}

            correct = flag.strip() == task.flag

            if correct and env_ref._tracker:
                env_ref._tracker.achieve_milestone("flag_captured")
                env_ref._step_reward = env_ref._tracker.update(
                    "submit_flag", {"flag": flag}, {"correct": True}
                )

            if env_ref._grader and env_ref._tracker:
                summary = env_ref._grader.grade_summary(env_ref._tracker)
            else:
                summary = {}

            env_ref._done = True

            return {
                "correct": correct,
                "message": "🎉 Flag captured! Well done!" if correct else "❌ Incorrect flag. Keep trying!",
                "score": summary.get("final_score", 0.0),
                "grade_summary": summary,
            }

        @mcp.tool
        def get_task_info() -> dict:
            """
            Get information about the current task.

            Returns the task name, description, difficulty, and hints.
            Use this at the beginning to understand your objective.

            Returns:
                Dictionary with task details including 'task_name',
                'description', 'difficulty', and initial hints.
            """
            task = env_ref._active_task
            if task is None:
                return {
                    "error": "No active task. Call start_task() first.",
                    "available_tasks": list(TASKS.keys()),
                }
            info = task.to_dict()
            # Progressive hints based on steps taken
            if env_ref._tracker and env_ref._tracker.total_steps > 10:
                info["hints"] = task.hints[:2]
            if env_ref._tracker and env_ref._tracker.total_steps > 20:
                info["hints"] = task.hints
            return info

        @mcp.tool
        def start_task(task_name: str = "sqli_login") -> dict:
            """
            Initialize a CTF task and start the vulnerable application.

            IMPORTANT: Call this FIRST before using http_request.
            This sets up the target application and configures the challenge.

            Args:
                task_name: Which task to start. Options:
                           - "sqli_login" (Easy: SQL injection)
                           - "idor_privesc" (Medium: IDOR + privilege escalation)
                           - "payment_logic" (Hard: business logic flaw)

            Returns:
                Dictionary with task details and confirmation that the
                vulnerable application is running.
            """
            if task_name not in TASKS:
                return {
                    "error": f"Unknown task: {task_name}",
                    "available_tasks": list(TASKS.keys()),
                }

            # Stop any previous app
            env_ref._stop_vulnerable_app()

            # Set up task
            env_ref._active_task = TASKS[task_name]
            env_ref._tracker = RewardTracker(env_ref._active_task)
            env_ref._grader = TaskGrader(env_ref._active_task)
            env_ref._done = False
            env_ref._step_reward = 0.0
            env_ref._session_cookies = {}
            env_ref._state = State(
                episode_id=str(uuid4()),
                step_count=0,
            )

            # Start the vulnerable app
            env_ref._start_vulnerable_app()

            return {
                "status": "ready",
                "message": f"Task '{env_ref._active_task.display_name}' initialized!",
                "task": env_ref._active_task.to_dict(),
                "instructions": (
                    "The vulnerable web application is now running. "
                    "Use list_source_files() and view_source() to read the code. "
                    "Use http_request() to interact with the application. "
                    "Use submit_flag() when you find the flag."
                ),
            }

        # Pass MCP server to base class
        super().__init__(mcp)

        # State
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._active_task: BaseTask | None = None
        self._tracker: RewardTracker | None = None
        self._grader: TaskGrader | None = None
        self._done: bool = False
        self._step_reward: float = 0.0

        # Vulnerable app state
        self._vuln_app_thread: threading.Thread | None = None
        self._vuln_port: int = VULN_APP_PORT
        self._session_cookies: dict = {}
        self._db_path: str = ""

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Observation:
        """
        Reset the environment for a new episode.

        Args:
            seed: Optional random seed (unused)
            episode_id: Optional episode ID
            **kwargs: Must include 'task' to select which CTF challenge to run.
                      Valid tasks: 'sqli_login', 'idor_privesc', 'payment_logic'

        Returns:
            Observation with task description and available tools.
        """
        # Determine task
        task_name = kwargs.get("task", "sqli_login")
        if task_name not in TASKS:
            return Observation(
                done=True,
                reward=0.0,
                metadata={
                    "error": f"Unknown task: {task_name}",
                    "available_tasks": list(TASKS.keys()),
                },
            )

        # Stop previous vulnerable app if running
        self._stop_vulnerable_app()

        # Set up new episode
        self._active_task = TASKS[task_name]
        self._tracker = RewardTracker(self._active_task)
        self._grader = TaskGrader(self._active_task)
        self._done = False
        self._step_reward = 0.0
        self._session_cookies = {}

        self._state = State(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
        )

        # Initialize database and start vulnerable app
        self._start_vulnerable_app()

        return Observation(
            done=False,
            reward=0.0,
            metadata={
                "status": "ready",
                "message": f"CTF Environment ready! Task: {self._active_task.display_name}",
                "task": self._active_task.to_dict(),
                "available_tools": [
                    "list_source_files",
                    "view_source",
                    "http_request",
                    "submit_flag",
                    "get_task_info",
                ],
                "instructions": (
                    "You are an AI security researcher. Your goal is to find and exploit "
                    "vulnerabilities in a web application. Start by listing source files "
                    "and reading the code. Then craft HTTP requests to exploit vulnerabilities "
                    "and capture the flag. Use submit_flag() when you find it."
                ),
            },
        )

    def _start_vulnerable_app(self):
        """Start the vulnerable Flask app in a background thread."""
        from .vulnerable_app.database import init_database, set_db_path
        from .vulnerable_app.app import create_vulnerable_app

        # Create a fresh database for this episode
        self._db_path = os.path.join(
            tempfile.gettempdir(), f"ctf_vuln_{self._state.episode_id}.db"
        )
        init_database(self._db_path)

        # Create Flask app
        app = create_vulnerable_app()
        app.config["TESTING"] = False

        # Find an available port
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            self._vuln_port = s.getsockname()[1]

        # Use a threading event for readiness signaling
        ready_event = threading.Event()

        def run_flask():
            """Run Flask with a ready callback."""
            from werkzeug.serving import make_server
            server = make_server(VULN_APP_HOST, self._vuln_port, app)
            server.timeout = 1
            ready_event.set()  # Signal that the server is bound and ready
            server.serve_forever()

        self._vuln_app_thread = threading.Thread(target=run_flask, daemon=True)
        self._vuln_app_thread.start()

        # Wait for the ready signal (non-polling, very fast)
        ready_event.wait(timeout=10)

    def _stop_vulnerable_app(self):
        """Stop the vulnerable Flask app and clean up."""
        # Clean up database file
        if self._db_path and os.path.exists(self._db_path):
            try:
                os.remove(self._db_path)
            except OSError:
                pass
            for suffix in ["-wal", "-shm"]:
                wal = self._db_path + suffix
                if os.path.exists(wal):
                    try:
                        os.remove(wal)
                    except OSError:
                        pass

        # Thread is daemonic, will be garbage collected
        self._vuln_app_thread = None

    def _step_impl(
        self,
        action: Action,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> Observation:
        """Handle non-MCP actions (fallback)."""
        return Observation(
            done=False,
            reward=0.0,
            metadata={
                "error": f"Unknown action type: {type(action).__name__}. "
                "Use MCP tools: list_source_files, view_source, http_request, submit_flag, get_task_info."
            },
        )

    def step(
        self,
        action: Action,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> Observation:
        """
        Execute a step in the environment.

        Increments step count, checks for max steps, and delegates to
        the MCP tool handling in the base class.
        """
        self._state.step_count += 1
        self._step_reward = 0.0

        # Check max steps
        if self._state.step_count >= MAX_STEPS_PER_EPISODE:
            self._done = True
            score = self._grader.grade(self._tracker) if self._grader and self._tracker else 0.0
            return Observation(
                done=True,
                reward=score,
                metadata={
                    "message": "Maximum steps reached. Episode ended.",
                    "final_score": score,
                    "tracker_summary": self._tracker.get_summary() if self._tracker else {},
                },
            )

        # Delegate to MCPEnvironment for tool handling
        obs = super().step(action, timeout_s=timeout_s, **kwargs)

        # Attach reward and done status to observation
        if self._done:
            score = self._grader.grade(self._tracker) if self._grader and self._tracker else 0.0
            obs.done = True
            obs.reward = score
        else:
            obs.reward = self._step_reward

        return obs

    async def step_async(
        self,
        action: Action,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> Observation:
        """Async step used by the WebSocket handler."""
        self._state.step_count += 1
        self._step_reward = 0.0

        if self._state.step_count >= MAX_STEPS_PER_EPISODE:
            self._done = True
            score = self._grader.grade(self._tracker) if self._grader and self._tracker else 0.0
            return Observation(
                done=True,
                reward=score,
                metadata={
                    "message": "Maximum steps reached. Episode ended.",
                    "final_score": score,
                    "tracker_summary": self._tracker.get_summary() if self._tracker else {},
                },
            )

        obs = await super().step_async(action, timeout_s=timeout_s, **kwargs)

        if self._done:
            score = self._grader.grade(self._tracker) if self._grader and self._tracker else 0.0
            obs.done = True
            obs.reward = score
        else:
            obs.reward = self._step_reward

        return obs

    @property
    def state(self) -> State:
        """Get the current environment state."""
        return self._state

    def close(self):
        """Clean up resources."""
        self._stop_vulnerable_app()
