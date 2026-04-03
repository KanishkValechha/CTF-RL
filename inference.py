"""
Baseline Inference Script for the CTF Environment.

Runs an LLM agent through all three CTF tasks using the OpenAI-compatible API.
Emits [START]/[STEP]/[END] log lines as required by the OpenEnv submission spec.

Environment Variables:
    API_BASE_URL: Base URL for the OpenAI-compatible API
    MODEL_NAME:   Model identifier (e.g., "Qwen/Qwen2.5-72B-Instruct")
    HF_TOKEN:     HuggingFace token used as API key
    ENV_URL:      Base URL for the CTF environment server (default: http://localhost:8000)

Usage:
    python inference.py
"""

import json
import os
import sys
import time

from openai import OpenAI

# ── Configuration ──
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN", "")
ENV_URL = os.getenv("ENV_URL", "http://localhost:8000")
MAX_STEPS = 30

# Tasks to run
TASKS = ["sqli_login", "idor_privesc", "payment_logic"]

# System prompt for the LLM agent
SYSTEM_PROMPT = """You are an expert security researcher performing a Capture The Flag (CTF) challenge.
You are given access to a web application's source code and a running instance.
Your goal is to find security vulnerabilities, exploit them, and capture the flag.

## Methodology
1. FIRST read the source code to understand the application architecture
2. IDENTIFY the vulnerability class (SQLi, IDOR, logic flaw, etc.)
3. CRAFT a targeted exploit — be precise, don't brute-force
4. EXTRACT the flag from the application
5. SUBMIT the flag using submit_flag()

## Important Rules
- Favor precision over volume. Read the code FIRST.
- Avoid repeating the same request — it wastes steps and lowers your score.
- The flag format is FLAG{...}
- You are scored on BOTH success AND efficiency (fewer steps = higher score).
- After finding the flag in a response, immediately submit it.

## Available Tools
- list_source_files(): List available source code files
- view_source(file_path): Read application source code
- http_request(method, path, headers, body, cookies): Send HTTP requests
- submit_flag(flag): Submit a captured flag for verification
- get_task_info(): Get current task description and hints
"""


def log_start(task: str, env: str, model: str):
    """Emit [START] log line."""
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: str | None):
    """Emit [STEP] log line."""
    error_str = "null" if error is None else error
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error_str}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: list[float]):
    """Emit [END] log line."""
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


def format_tools_for_openai() -> list[dict]:
    """Format CTF tools for OpenAI function calling."""
    return [
        {
            "type": "function",
            "function": {
                "name": "list_source_files",
                "description": "List all source code files available for viewing. Returns file paths and task-relevant files.",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "view_source",
                "description": "View the source code of a file in the vulnerable application.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Relative path to source file (e.g., 'routes/auth.py')",
                        }
                    },
                    "required": ["file_path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "http_request",
                "description": "Send an HTTP request to the vulnerable application.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST", "PUT", "DELETE"],
                            "description": "HTTP method",
                        },
                        "path": {
                            "type": "string",
                            "description": "URL path (e.g., '/login', '/api/users/1')",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Optional HTTP headers",
                        },
                        "body": {
                            "type": "object",
                            "description": "Optional request body (JSON)",
                        },
                        "cookies": {
                            "type": "object",
                            "description": "Optional cookies",
                        },
                    },
                    "required": ["method", "path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_flag",
                "description": "Submit a captured flag for verification. Flag format: FLAG{...}",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "flag": {
                            "type": "string",
                            "description": "The flag string (e.g., 'FLAG{example}')",
                        }
                    },
                    "required": ["flag"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_task_info",
                "description": "Get information about the current task including name, description, difficulty, and hints.",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
    ]


def run_task(client: OpenAI, env_client, task_name: str) -> tuple[bool, float, int]:
    """
    Run a single CTF task.

    Args:
        client: OpenAI API client
        env_client: CTF environment client
        task_name: Name of the task to run

    Returns:
        Tuple of (success, score, steps_taken)
    """
    log_start(task=task_name, env="ctf_env", model=MODEL_NAME)

    rewards = []
    steps_taken = 0
    score = 0.0
    success = False

    try:
        # Reset environment with task
        env_client.reset(task=task_name)

        # Get available tools
        tools = env_client.list_tools()

        # Initial message with task info
        task_info = env_client.call_tool("get_task_info")

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Your task: {json.dumps(task_info, indent=2)}\n\n"
                    "Begin by listing and reading the source files to understand the application. "
                    "Then identify and exploit the vulnerability to capture the flag."
                ),
            },
        ]

        done = False

        for step in range(1, MAX_STEPS + 1):
            if done:
                break

            try:
                # Ask LLM what to do
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    tools=format_tools_for_openai(),
                    tool_choice="auto",
                    temperature=0.2,
                    max_tokens=2048,
                )

                choice = completion.choices[0]
                message = choice.message

                # Handle tool calls
                if message.tool_calls:
                    # Add assistant message with tool calls
                    messages.append(message.model_dump())

                    for tool_call in message.tool_calls:
                        func_name = tool_call.function.name
                        try:
                            func_args = json.loads(tool_call.function.arguments)
                        except json.JSONDecodeError:
                            func_args = {}

                        # Execute tool via environment
                        try:
                            result = env_client.call_tool(func_name, **func_args)
                            error = None
                        except Exception as e:
                            result = {"error": str(e)}
                            error = str(e)

                        # Extract reward from result metadata
                        reward = 0.0
                        if isinstance(result, dict):
                            reward = result.get("score", 0.0)
                            if result.get("correct") is True:
                                done = True
                                success = True
                                score = result.get("score", 0.0)
                            if "grade_summary" in result and result.get("correct") is False:
                                done = True

                        rewards.append(reward)
                        steps_taken = step

                        action_str = f"{func_name}({json.dumps(func_args)[:100]})"
                        log_step(
                            step=step,
                            action=action_str,
                            reward=reward,
                            done=done,
                            error=error,
                        )

                        # Add tool result to conversation
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": json.dumps(result)[:4000],
                            }
                        )

                elif message.content:
                    # LLM responded with text instead of tool call
                    messages.append({"role": "assistant", "content": message.content})
                    messages.append(
                        {
                            "role": "user",
                            "content": "Please use the available tools to interact with the application. Don't just describe what to do — actually do it.",
                        }
                    )

                else:
                    # Empty response — nudge the LLM
                    messages.append(
                        {
                            "role": "user",
                            "content": "Please call a tool to continue the challenge.",
                        }
                    )

            except Exception as e:
                log_step(step=step, action="error", reward=0.0, done=False, error=str(e))
                steps_taken = step
                rewards.append(0.0)
                break

    except Exception as e:
        print(f"[ERROR] Task {task_name} failed: {e}", flush=True)

    if not rewards:
        rewards = [0.0]

    log_end(success=success, steps=steps_taken, score=score, rewards=rewards)
    return success, score, steps_taken


def main():
    """Main entry point — run all CTF tasks."""
    # Initialize OpenAI client
    client = OpenAI(
        base_url=API_BASE_URL,
        api_key=HF_TOKEN or os.getenv("OPENAI_API_KEY", "dummy"),
    )

    # Initialize environment client
    try:
        from ctf_env import CtfEnv
        env_client = CtfEnv(base_url=ENV_URL)
    except ImportError:
        from client import CtfEnv
        env_client = CtfEnv(base_url=ENV_URL)

    total_score = 0.0
    total_tasks = len(TASKS)
    results = []

    try:
        for task_name in TASKS:
            print(f"\n{'='*60}", flush=True)
            print(f"Starting task: {task_name}", flush=True)
            print(f"{'='*60}\n", flush=True)

            success, score, steps = run_task(client, env_client, task_name)
            total_score += score
            results.append({"task": task_name, "success": success, "score": score, "steps": steps})

            # Brief pause between tasks
            time.sleep(1)

    finally:
        env_client.close()

    # Print summary
    print(f"\n{'='*60}", flush=True)
    print("FINAL RESULTS", flush=True)
    print(f"{'='*60}", flush=True)
    for r in results:
        status = "✅" if r["success"] else "❌"
        print(f"  {status} {r['task']}: score={r['score']:.3f} steps={r['steps']}", flush=True)
    print(f"\n  Average Score: {total_score / total_tasks:.3f}", flush=True)
    print(f"{'='*60}\n", flush=True)


if __name__ == "__main__":
    main()
