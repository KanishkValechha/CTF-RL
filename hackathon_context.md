# OpenEnv Next-Gen Hackathon Context Transfer
**Project Name:** AI CTF / Vulnerability Discovery Sandbox  
**Framework:** OpenEnv (Model Context Protocol - MCP)

This document captures the project context, architecture, and the benchmark assumptions a reviewer or judge needs in order to understand and run the environment correctly.

---

## 1. Core Idea
An AI security researcher is dropped into a sandboxed vulnerable application with:
- source code access,
- a live running service,
- flags hidden behind security flaws,
- a deterministic reward function that values both correctness and good methodology.

The official benchmark flow focuses on 3 tasks:
1. Easy: SQL injection login bypass
2. Medium: IDOR plus privilege escalation
3. Hard: Payment logic flaw

The repo also includes extra local-only validation tasks for broader coverage.

---

## 2. Hackathon Requirements

### Requirement 1: Containerized and Hugging Face Ready
- **Rule:** The environment must run in a Hugging Face Space using the OpenEnv Docker base image.
- **Check:** `Dockerfile` uses `ghcr.io/meta-pytorch/openenv-base`, installs Python with `uv`, installs Node.js for the vulnerable app, and serves `server.app:app` on port `8000`.

### Requirement 2: Deterministic Scoring in `[0.0, 1.0]`
- **Rule:** Rewards must stay within `[0.0, 1.0]`.
- **Check:** `RewardTracker` and `TaskGrader` combine milestone credit, flag capture, elegance bonus, and noise penalty, then clamp to `[0.0, 1.0]`.
- **Important implementation note:** Partial grading is exposed through OpenEnv step rewards. The baseline solver must consume step observations, not raw `call_tool()` return values, or milestone credit will be hidden from logs.

### Requirement 3: MCP Tool Compatibility
- **Rule:** The environment must expose structured tools rather than raw string actions.
- **Check:** The environment provides `start_task`, `list_source_files`, `view_source`, `http_request`, `submit_flag`, and `get_task_info` through FastMCP/OpenEnv.

### Requirement 4: Standardized Judge Logs
- **Rule:** `inference.py` must emit `[START]`, `[STEP]`, and `[END]` logs to stdout.
- **Check:** `inference.py` now logs one `[STEP]` per tool invocation and preserves partial rewards and terminal `done` state by using the OpenEnv step API.

### Requirement 5: Stateless Repetition
- **Rule:** The environment must reset cleanly between runs.
- **Check:** Each task reset tears down the old vulnerable app, creates a fresh SQLite database, and starts a new per-episode Node.js process on a new ephemeral port.

---

## 3. Architecture

**Wrapper:**  
`server/app.py` exposes the environment over OpenEnv/FastAPI.

**Target application:**  
`server/vulnerable_app/` is a deliberately vulnerable Node.js/Express e-commerce API launched as a subprocess by `CTFEnvironment`.

**Benchmark task paths:**
1. **SQLi login:** `POST /api/auth/login` allows classic login-bypass SQL injection.
2. **IDOR plus privesc:** `GET /api/users/:id` leaks arbitrary profiles and `PUT /api/users/:id` allows mass assignment.
3. **Payment logic:** `POST /api/cart/add` and `POST /api/checkout` allow negative quantity exploitation.

**Grading model:**  
`server/reward.py` tracks milestones such as reading relevant source, hitting the vulnerable endpoint, exploiting the bug, and submitting the flag. `server/graders.py` produces the final deterministic score.

---

## 4. How Judges Will Evaluate It
1. They run the environment locally or in a Hugging Face Space.
2. They point their own LLM baseline at the environment URL.
3. They run `inference.py` and parse `[START]`, `[STEP]`, and `[END]`.

To match the spec correctly:
- the environment must expose valid tool schemas,
- HTTP interactions must remain stable across resets,
- milestone rewards must appear during the run,
- final scores must remain deterministic.

Local validation now covers both exploit success and scoring semantics:
- `test_integration.py` validates 7 exploit paths plus a reward-progression regression check,
- the 3 official benchmark tasks still remain the primary submission path.
