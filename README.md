---
title: OpenEnv Web Security Benchmark
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
app_port: 8000
tags:
  - openenv
  - security
  - benchmark
  - agent-evaluation
  - cybersecurity
---

# OpenEnv Web Security Benchmark

A **10-task web-security agent benchmark** for OpenEnv, built around a realistic vulnerable Node.js application and a stable judge-facing tool contract.

Each episode launches a fresh target app, lets the agent inspect source and send HTTP requests, and returns deterministic rewards in **`[0.0, 1.0]`**.

## Quick links

- GitHub repo: [swar16/MetaHack-CTFEnv](https://github.com/swar16/MetaHack-CTFEnv)
- Hugging Face Space: [swar16/ctf_env](https://huggingface.co/spaces/swar16/ctf_env)
- Live Space URL: [https://swar16-ctf-env.hf.space](https://swar16-ctf-env.hf.space)

## Why this benchmark is useful

- models a real agent workflow: read code, trace auth paths, exploit the app, and prove impact
- spans varied security domains: SQLi, IDOR, business-logic abuse, JWT misuse, SSRF, XSS, path traversal, and unsafe import/deserialization
- uses **partial, deterministic milestone grading**, not just sparse binary flag capture
- tracks exploit quality via `precision_bonus`, `noise_penalty`, and `detection_risk`

## Benchmark surface

The public tool contract is intentionally stable and judge-friendly:
- `list_source_files`
- `view_source`
- `http_request`
- `submit_flag`
- `get_task_info`
- `start_task`

The main benchmark trio used by `inference.py` remains:
- `sqli_login`
- `idor_privesc`
- `payment_logic`

The full local benchmark exposes 10 tasks:

| Task | Difficulty | Theme |
| --- | --- | --- |
| `sqli_login` | easy | login bypass via SQL injection |
| `sqli_union` | medium | UNION-based data extraction |
| `idor_privesc` | medium | IDOR plus mass-assignment privilege escalation |
| `payment_logic` | hard | negative-quantity checkout logic flaw |
| `command_injection` | medium | command execution in admin export |
| `jwt_forgery` | medium | forged admin JWT using weak secret |
| `ssrf` | hard | authenticated SSRF with internal pivot ticket |
| `xss_stored` | medium | stored XSS in product reviews |
| `path_traversal` | medium | file read outside uploads directory |
| `deserialization` | hard | authenticated unsafe import with stored job retrieval |

## Reward design

Scoring is deterministic and bounded:
- every step reward is in **`[0.0, 1.0]`**
- final episode score is in **`[0.0, 1.0]`**
- graders only award milestones when task-specific evidence is present
- summaries expose:
  - `final_score`
  - `milestones_achieved`
  - `milestones_missed`
  - `precision_bonus`
  - `noise_penalty`
  - `detection_risk`

This keeps the environment faithful to the hackathon grading expectations while still offering meaningful intermediate learning signal.

## Validation snapshot

The current public build is validated end to end:
- `openenv validate` passes
- local `test_integration.py` passes all `16/16` checks
- Docker builds successfully and serves healthy `/schema` and `/reset` endpoints
- the public Hugging Face Space is running on the synced benchmark snapshot

## Project layout

```text
CTF-RL/
├── Dockerfile
├── openenv.yaml
├── inference.py
├── test_integration.py
├── models.py
├── server/
│   ├── app.py
│   ├── ctf_environment.py
│   ├── reward.py
│   ├── graders.py
│   ├── tasks/
│   └── vulnerable_app/
└── client.py
```

## Local setup

Prerequisites:
- Python 3.10+
- Node.js 18+
- `uv`

Install Python dependencies:

```bash
uv sync
```

Run the OpenEnv server locally:

```bash
uv run server
```

The environment serves the OpenEnv/FastAPI app on port `8000`.

## Integration validation

Run the end-to-end suite against the local server:

```bash
uv run python test_integration.py
```

The suite covers:
- all 10 exposed tasks
- partial reward progression
- negative-credit checks for near misses
- deterministic reward traces
- reset isolation
- score-bound invariants

Additional validation commands:

```bash
openenv validate
uv run python -m py_compile __init__.py inference.py test_integration.py
docker build -t ctf-rl-local .
```

## Inference contract

`inference.py` preserves the Phase 1/2 submission contract:

Required environment variables:
- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`

Optional environment variables:
- `LOCAL_IMAGE_NAME`
- `ENV_URL`

The script configures the OpenAI-compatible client from those variables and writes only structured log lines on stdout:
- `[START]`
- `[STEP]`
- `[END]`

Example local run:

```bash
set API_BASE_URL=https://your-openai-compatible-endpoint
set MODEL_NAME=your-model-name
set HF_TOKEN=your-api-key
set ENV_URL=http://localhost:8000
uv run python inference.py
```

## Hugging Face Space deployment

The benchmark is packaged for a Docker Space. The validated public deployment is:
- Space repo: [swar16/ctf_env](https://huggingface.co/spaces/swar16/ctf_env)
- Live URL: [https://swar16-ctf-env.hf.space](https://swar16-ctf-env.hf.space)

To deploy your own copy:

```bash
uv run hf repos create <username>/ctf-env --type space --space-sdk docker --public
openenv push --repo-id <username>/ctf-env
```

Judge-facing checks to keep green:
- `POST /reset` returns `200`
- `/schema` returns `200`
- repo-root `Dockerfile` builds successfully
- `openenv validate` passes

## Submission notes

This repository keeps the judge-facing contracts stable:
- `openenv.yaml` remains unchanged
- Docker still serves the app on port `8000`
- the benchmark trio in `inference.py` is unchanged
- all public tool names and response semantics remain additive-compatible
- partial reward reporting now reflects the environment's true milestone grading

If you want to extend the benchmark further after submission, the safest next step is to add new tasks or stronger hard-mode variants without changing the existing tool or scoring contract.
