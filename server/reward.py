"""
Reward Tracker and Noise Detector.

Tracks agent progress through milestones, detects noise actions,
and calculates rewards for the CTF environment.

Supports milestone detection for all 10 tasks:
- sqli_login, sqli_union, idor_privesc, payment_logic
- command_injection, jwt_forgery, ssrf, xss_stored
- path_traversal, deserialization
"""

import re
from collections import Counter
from typing import Any

from .tasks.base_task import BaseTask


class NoiseDetector:
    """
    Detects unproductive 'noise' actions — random hammering without progress.

    Noise actions include:
    - Hitting the same endpoint >5 times without making progress
    - Sending identical payloads
    - Sending excessively long/random payloads
    """

    def __init__(self):
        self.endpoint_hits: Counter = Counter()
        self.payload_hashes: Counter = Counter()
        self.progress_checkpoints: list[int] = [0]

    def reset(self):
        """Reset noise detection state."""
        self.endpoint_hits.clear()
        self.payload_hashes.clear()
        self.progress_checkpoints = [0]

    def is_noise(self, action_name: str, action_args: dict, current_milestone_count: int) -> bool:
        """
        Determine if an action is noise.

        Args:
            action_name: The tool name called.
            action_args: The arguments passed.
            current_milestone_count: How many milestones have been achieved.

        Returns:
            True if the action is noise.
        """
        # Only http_request actions can be noise
        if action_name != "http_request":
            return False

        path = action_args.get("path", "")
        method = action_args.get("method", "GET")
        endpoint_key = f"{method} {path}"

        # Track endpoint hits
        self.endpoint_hits[endpoint_key] += 1

        # 1. Same endpoint hit >5 times without milestone progress
        if self.endpoint_hits[endpoint_key] > 5:
            if current_milestone_count <= self.progress_checkpoints[-1]:
                return True

        # 2. Exact same payload sent (hash of full action)
        payload_hash = hash(str(sorted(action_args.items())))
        self.payload_hashes[payload_hash] += 1
        if self.payload_hashes[payload_hash] > 1:
            return True

        # 3. Excessively long body (fuzzing signature)
        body = str(action_args.get("body", ""))
        if len(body) > 1000:
            return True

        # Update progress checkpoint
        self.progress_checkpoints.append(current_milestone_count)
        return False


class RewardTracker:
    """
    Tracks agent progress and calculates cumulative rewards.

    Manages:
    - Milestone tracking (which checkpoints have been achieved)
    - Step counting
    - Noise detection and penalty
    - Elegance bonus calculation
    """

    def __init__(self, task: BaseTask):
        self.task = task
        self.milestones_achieved: set[str] = set()
        self.total_steps: int = 0
        self.noise_count: int = 0
        self.source_files_read: set[str] = set()
        self.endpoints_hit: Counter = Counter()
        self.noise_detector = NoiseDetector()
        self._last_reward: float = 0.0

    def reset(self):
        """Reset the tracker for a new episode."""
        self.milestones_achieved.clear()
        self.total_steps = 0
        self.noise_count = 0
        self.source_files_read.clear()
        self.endpoints_hit.clear()
        self.noise_detector.reset()
        self._last_reward = 0.0

    def update(self, action_name: str, action_args: dict, result: dict) -> float:
        """
        Update tracker state after a step and return differential reward.

        Args:
            action_name: The tool name called (e.g., "view_source").
            action_args: The tool arguments.
            result: The result dictionary from the tool.

        Returns:
            Differential reward for this step.
        """
        self.total_steps += 1
        previous_reward = self.calculate_reward()

        # Check for noise
        if self.noise_detector.is_noise(action_name, action_args, len(self.milestones_achieved)):
            self.noise_count += 1

        # Track source files read
        if action_name == "view_source":
            file_path = action_args.get("file_path", "")
            self.source_files_read.add(file_path)

        # Track endpoints hit
        if action_name == "http_request":
            path = action_args.get("path", "")
            method = action_args.get("method", "GET")
            self.endpoints_hit[f"{method} {path}"] += 1

        # Check milestones
        self._check_milestones(action_name, action_args, result)

        current_reward = self.calculate_reward()
        diff = current_reward - previous_reward
        self._last_reward = current_reward
        return diff

    def _check_milestones(self, action_name: str, action_args: dict, result: dict):
        """
        Check if any new milestones were achieved.

        Detects milestones across all 10 tasks based on action patterns.
        """

        # ── source_read ── (all tasks)
        if action_name == "view_source":
            file_path = action_args.get("file_path", "")
            for relevant in self.task.relevant_files:
                if relevant in file_path:
                    self.milestones_achieved.add("source_read")
                    break

        # ── HTTP request milestones ──
        if action_name == "http_request":
            path = action_args.get("path", "")
            method = action_args.get("method", "").upper()
            status = result.get("status_code", 0)
            body_arg = action_args.get("body", {}) or {}
            body_str = str(body_arg)
            headers_arg = action_args.get("headers", {}) or {}
            resp_body = result.get("body", {})
            if not isinstance(resp_body, dict):
                resp_body = {}

            # ═══════════════════════════════════════════════
            # SHARED MILESTONES (used by multiple tasks)
            # ═══════════════════════════════════════════════

            # ── account_created ──
            if method == "POST" and "/api/auth/register" in path and status in (200, 201):
                self.milestones_achieved.add("account_created")

            # ── auth_obtained ──
            # Any successful login or registration gives auth
            if method == "POST" and ("/api/auth/login" in path or "/api/auth/register" in path) and status in (200, 201):
                if isinstance(resp_body, dict) and resp_body.get("token"):
                    self.milestones_achieved.add("auth_obtained")

            # ═══════════════════════════════════════════════
            # TASK: sqli_login
            # ═══════════════════════════════════════════════

            # ── vuln_endpoint_targeted (sqli_login) ──
            if method == "POST" and "/api/auth/login" in path:
                self.milestones_achieved.add("vuln_endpoint_targeted")

            # ── sqli_payload_sent ──
            sqli_patterns = [r"'", r"OR\s+1\s*=\s*1", r"--", r"UNION", r"SELECT", r"DROP"]
            if method == "POST" and "/api/auth/login" in path:
                for pattern in sqli_patterns:
                    if re.search(pattern, body_str, re.IGNORECASE):
                        self.milestones_achieved.add("sqli_payload_sent")
                        break

            # ── auth_bypassed ──
            if "/api/auth/login" in path and status == 200:
                if isinstance(resp_body, dict) and resp_body.get("role") == "admin":
                    self.milestones_achieved.add("auth_bypassed")

            # ═══════════════════════════════════════════════
            # TASK: sqli_union
            # ═══════════════════════════════════════════════

            # ── vuln_endpoint_targeted (sqli_union - product search) ──
            if method == "GET" and "/api/products" in path and ("search" in path or "search" in str(body_arg)):
                self.milestones_achieved.add("vuln_endpoint_targeted")

            # ── union_payload_sent ──
            union_patterns = [r"UNION\s+SELECT", r"UNION\s+ALL\s+SELECT"]
            full_path_str = path + "?" + str(body_arg)
            for pattern in union_patterns:
                if re.search(pattern, full_path_str, re.IGNORECASE):
                    self.milestones_achieved.add("union_payload_sent")
                    break

            # ── data_extracted (flags table data in response) ──
            if "/api/products" in path and status == 200:
                resp_str = str(resp_body)
                if "FLAG{" in resp_str:
                    self.milestones_achieved.add("data_extracted")

            # ═══════════════════════════════════════════════
            # TASK: idor_privesc
            # ═══════════════════════════════════════════════

            # ── idor_exploited ──
            if re.search(r"/api/users/\d+", path) and method == "GET" and status == 200:
                self.milestones_achieved.add("idor_exploited")
                # Check if admin data was found
                user_data = resp_body.get("user", resp_body) if isinstance(resp_body, dict) else {}
                if isinstance(user_data, dict) and user_data.get("role") == "admin":
                    self.milestones_achieved.add("admin_data_found")

            # ── privilege_escalated ──
            if re.search(r"/api/users/\d+", path) and method == "PUT" and status == 200:
                if isinstance(body_arg, dict) and (body_arg.get("role") == "admin" or body_arg.get("is_admin") == 1):
                    self.milestones_achieved.add("privilege_escalated")

            # ═══════════════════════════════════════════════
            # TASK: payment_logic
            # ═══════════════════════════════════════════════

            # ── products_enumerated ──
            if "/api/products" in path and method == "GET" and status == 200:
                self.milestones_achieved.add("products_enumerated")

            # ── cart_manipulated ──
            if "/api/cart/add" in path and method == "POST" and status == 200:
                self.milestones_achieved.add("cart_manipulated")

            # ── logic_flaw_exploited (negative quantity) ──
            if "/api/cart/add" in path and method == "POST":
                if isinstance(body_arg, dict):
                    qty = body_arg.get("quantity", 1)
                    if isinstance(qty, (int, float)) and qty < 0:
                        self.milestones_achieved.add("logic_flaw_exploited")
                    # Also detect price manipulation
                    if body_arg.get("price") is not None:
                        self.milestones_achieved.add("logic_flaw_exploited")

            # ── logic_flaw_exploited (discount stacking) ──
            if "/api/cart/apply-discount" in path and method == "POST":
                discount_count = self.endpoints_hit.get("POST /api/cart/apply-discount", 0)
                if discount_count >= 2:
                    self.milestones_achieved.add("logic_flaw_exploited")

            # ── negative_total_achieved ──
            if "/api/checkout" in path and method == "POST" and status == 200:
                if isinstance(resp_body, dict):
                    total = resp_body.get("total", 1)
                    if isinstance(total, (int, float)) and total <= 0:
                        self.milestones_achieved.add("negative_total_achieved")

            # ═══════════════════════════════════════════════
            # TASK: command_injection
            # ═══════════════════════════════════════════════

            # ── vuln_endpoint_targeted (admin export) ──
            if "/api/admin/export" in path and method == "POST":
                self.milestones_achieved.add("vuln_endpoint_targeted")

            # ── cmd_payload_sent ──
            cmd_patterns = [r"[;|&`]", r"\$\(", r"cat\s+", r"ls\s+", r"echo\s+", r"/bin/", r"flag\.txt"]
            if "/api/admin/export" in path and method == "POST":
                for pattern in cmd_patterns:
                    if re.search(pattern, body_str, re.IGNORECASE):
                        self.milestones_achieved.add("cmd_payload_sent")
                        break

            # ═══════════════════════════════════════════════
            # TASK: jwt_forgery
            # ═══════════════════════════════════════════════

            # ── secret_discovered ──
            # Detected when agent reads config.js (source_read covers this)
            if action_name == "view_source":
                file_path = action_args.get("file_path", "")
                if "config.js" in file_path:
                    self.milestones_achieved.add("secret_discovered")

            # ── token_forged ──
            # Detect custom Authorization header with admin access to admin endpoints
            if "/api/admin/" in path and method == "GET" and status == 200:
                auth_header = headers_arg.get("Authorization", "") or headers_arg.get("authorization", "")
                if auth_header.startswith("Bearer "):
                    self.milestones_achieved.add("token_forged")

            # ═══════════════════════════════════════════════
            # TASK: ssrf
            # ═══════════════════════════════════════════════

            # ── vuln_endpoint_targeted (fetch-url) ──
            if "/api/admin/fetch-url" in path and method == "POST":
                self.milestones_achieved.add("vuln_endpoint_targeted")

            # ── ssrf_payload_sent ──
            ssrf_patterns = [r"http://127\.0\.0\.1", r"http://localhost", r"http://0\.0\.0\.0", r"http://\[::1\]"]
            if "/api/admin/fetch-url" in path and method == "POST":
                for pattern in ssrf_patterns:
                    if re.search(pattern, body_str, re.IGNORECASE):
                        self.milestones_achieved.add("ssrf_payload_sent")
                        break

            # ── internal_accessed ──
            if "/api/admin/fetch-url" in path and method == "POST" and status == 200:
                resp_str = str(resp_body)
                if "internal_access_granted" in resp_str or "FLAG{" in resp_str:
                    self.milestones_achieved.add("internal_accessed")

            # ═══════════════════════════════════════════════
            # TASK: xss_stored
            # ═══════════════════════════════════════════════

            # ── xss_payload_sent ──
            xss_patterns = [r"<script", r"onerror\s*=", r"onload\s*=", r"javascript:", r"<img", r"<svg", r"<iframe"]
            if "/api/reviews" in path and method == "POST":
                for pattern in xss_patterns:
                    if re.search(pattern, body_str, re.IGNORECASE):
                        self.milestones_achieved.add("xss_payload_sent")
                        break

            # ── xss_stored ──
            if "/api/reviews" in path and method == "POST" and status in (200, 201):
                if isinstance(resp_body, dict) and resp_body.get("flag"):
                    self.milestones_achieved.add("xss_stored")

            # ═══════════════════════════════════════════════
            # TASK: path_traversal
            # ═══════════════════════════════════════════════

            # ── vuln_endpoint_targeted (files) ──
            if "/api/files/" in path and method == "GET":
                self.milestones_achieved.add("vuln_endpoint_targeted")

            # ── traversal_payload_sent ──
            if "/api/files/" in path and method == "GET":
                if ".." in path:
                    self.milestones_achieved.add("traversal_payload_sent")

            # ── file_read ──
            if "/api/files/" in path and method == "GET" and status == 200:
                resp_str = str(resp_body)
                if "FLAG{" in resp_str or "flag" in path.lower():
                    self.milestones_achieved.add("file_read")

            # ═══════════════════════════════════════════════
            # TASK: deserialization
            # ═══════════════════════════════════════════════

            # ── vuln_endpoint_targeted (import) ──
            if "/api/import" in path and method == "POST":
                self.milestones_achieved.add("vuln_endpoint_targeted")

            # ── payload_crafted ──
            if "/api/import" in path and method == "POST":
                if isinstance(body_arg, dict) and body_arg.get("data"):
                    self.milestones_achieved.add("payload_crafted")

            # ── code_executed ──
            if "/api/import" in path and method == "POST" and status == 200:
                if isinstance(resp_body, dict) and resp_body.get("status") == "import_completed":
                    result_data = str(resp_body.get("result", ""))
                    if "FLAG{" in result_data or len(result_data) > 10:
                        self.milestones_achieved.add("code_executed")

        # ── flag_captured (checked externally via submit_flag) ──

    def achieve_milestone(self, name: str):
        """Manually mark a milestone as achieved (used by submit_flag)."""
        self.milestones_achieved.add(name)

    def calculate_reward(self) -> float:
        """
        Calculate current cumulative reward — strictly within (0.0, 1.0).

        The OpenEnv spec requires scores to be strictly between 0 and 1
        (exclusive on both ends: not 0.0 and not 1.0).

        The reward is built so that 0.0 and 1.0 are naturally unreachable:
        - BASE_REWARD (0.01) ensures even a do-nothing agent scores above 0.
        - MILESTONE_SCALE (0.90) caps milestone contribution at 0.90, so
          even a perfect run with max elegance bonus tops out at ~0.99.
        - EPSILON is a last-resort safety net for extreme noise edge cases.

        Components:
        - Base participation reward: 0.01 (agent started the episode)
        - Milestone progress: sum of achieved milestones, scaled to max 0.90
        - Elegance bonus: efficiency reward (-0.04 to +0.08)
        - Noise penalty: unproductive action penalty (0.0 to 0.20)
        """
        EPSILON = 0.001      # Last-resort safety net
        BASE_REWARD = 0.01   # Participation credit — score is never 0
        MILESTONE_SCALE = 0.90  # Milestones contribute at most 0.90

        # Milestone progress (task files define weights summing to 1.0,
        # we scale down so the max milestone contribution is 0.90)
        task_milestones = {m.name: m.reward_value for m in self.task.milestones}
        milestone_sum = sum(task_milestones.get(name, 0) for name in self.milestones_achieved)

        # Elegance bonus
        elegance = self._elegance_bonus()

        # Noise penalty
        noise_penalty = self._noise_penalty()

        raw = BASE_REWARD + (milestone_sum * MILESTONE_SCALE) + elegance - noise_penalty
        # Safety net clamp — should rarely trigger with the above design
        return min(1.0 - EPSILON, max(EPSILON, round(raw, 4)))

    def _elegance_bonus(self) -> float:
        """
        Calculate elegance bonus based on step efficiency.

        Scaled so that the maximum bonus (0.08) keeps the total
        reward ceiling at ~0.99 (0.01 base + 0.90 milestones + 0.08).
        """
        if self.total_steps == 0 or "flag_captured" not in self.milestones_achieved:
            return 0.0

        ratio = self.total_steps / self.task.optimal_steps
        if ratio <= 1.5:
            return 0.08
        elif ratio <= 3.0:
            return 0.04
        elif ratio <= 5.0:
            return 0.0
        else:
            return -0.04

    def _noise_penalty(self) -> float:
        """Calculate noise penalty."""
        if self.total_steps == 0:
            return 0.0
        noise_ratio = self.noise_count / max(self.total_steps, 1)
        return min(0.2, noise_ratio * 0.3)

    def get_summary(self) -> dict:
        """Get a summary of the current tracking state."""
        return {
            "milestones_achieved": sorted(self.milestones_achieved),
            "total_milestones": len(self.task.milestones),
            "total_steps": self.total_steps,
            "noise_count": self.noise_count,
            "current_reward": self.calculate_reward(),
            "source_files_read": sorted(self.source_files_read),
        }
