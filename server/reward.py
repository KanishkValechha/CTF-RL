"""
Reward Tracker and Noise Detector.

Tracks agent progress through milestones, detects noise actions,
and calculates rewards for the CTF environment.
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
        """Check if any new milestones were achieved."""

        # ── source_read ──
        if action_name == "view_source":
            file_path = action_args.get("file_path", "")
            for relevant in self.task.relevant_files:
                if relevant in file_path:
                    self.milestones_achieved.add("source_read")
                    break

        # ── account_created ──
        if action_name == "http_request":
            path = action_args.get("path", "")
            method = action_args.get("method", "")
            status = result.get("status_code", 0)

            if method.upper() == "POST" and "/register" in path and status in (200, 201):
                self.milestones_achieved.add("account_created")

            # ── vuln_endpoint_targeted ──
            if method.upper() == "POST" and "/login" in path:
                self.milestones_achieved.add("vuln_endpoint_targeted")

            # ── sqli_payload_sent ──
            body_str = str(action_args.get("body", ""))
            sqli_patterns = [r"'", r"OR\s+1\s*=\s*1", r"--", r"UNION", r"SELECT", r"DROP"]
            if method.upper() == "POST" and "/login" in path:
                for pattern in sqli_patterns:
                    if re.search(pattern, body_str, re.IGNORECASE):
                        self.milestones_achieved.add("sqli_payload_sent")
                        break

            # ── auth_bypassed ──
            if "/login" in path and status == 200:
                body_data = result.get("body", {})
                if isinstance(body_data, dict) and body_data.get("role") == "admin":
                    self.milestones_achieved.add("auth_bypassed")

            # ── idor_exploited ──
            if re.search(r"/api/users/\d+", path) and method.upper() == "GET" and status == 200:
                self.milestones_achieved.add("idor_exploited")
                body_data = result.get("body", {})
                if isinstance(body_data, dict) and body_data.get("role") == "admin":
                    self.milestones_achieved.add("admin_data_found")

            # ── privilege_escalated ──
            if re.search(r"/api/users/\d+", path) and method.upper() == "PUT" and status == 200:
                body_arg = action_args.get("body", {})
                if isinstance(body_arg, dict) and body_arg.get("role") == "admin":
                    self.milestones_achieved.add("privilege_escalated")

            # ── products_enumerated ──
            if "/api/products" in path and method.upper() == "GET" and status == 200:
                self.milestones_achieved.add("products_enumerated")

            # ── cart_manipulated ──
            if "/api/cart/add" in path and method.upper() == "POST" and status == 200:
                self.milestones_achieved.add("cart_manipulated")

            # ── logic_flaw_exploited ──
            if "/api/cart/add" in path and method.upper() == "POST":
                body_arg = action_args.get("body", {})
                if isinstance(body_arg, dict):
                    qty = body_arg.get("quantity", 1)
                    if isinstance(qty, (int, float)) and qty < 0:
                        self.milestones_achieved.add("logic_flaw_exploited")

            if "/api/cart/apply-discount" in path and method.upper() == "POST":
                # Count how many times discount was applied
                discount_count = self.endpoints_hit.get("POST /api/cart/apply-discount", 0)
                if discount_count >= 2:
                    self.milestones_achieved.add("logic_flaw_exploited")

            # ── negative_total_achieved ──
            if "/api/checkout" in path and method.upper() == "POST" and status == 200:
                body_data = result.get("body", {})
                if isinstance(body_data, dict):
                    total = body_data.get("total", 1)
                    if isinstance(total, (int, float)) and total <= 0:
                        self.milestones_achieved.add("negative_total_achieved")

        # ── flag_captured (checked externally via submit_flag) ──

    def achieve_milestone(self, name: str):
        """Manually mark a milestone as achieved (used by submit_flag)."""
        self.milestones_achieved.add(name)

    def calculate_reward(self) -> float:
        """
        Calculate current cumulative reward (0.0 - 1.0).

        Components:
        - Milestone progress: sum of achieved milestone values
        - Elegance bonus: reward for efficiency
        - Noise penalty: penalty for unproductive actions
        """
        # Base: sum of milestone rewards
        task_milestones = {m.name: m.reward_value for m in self.task.milestones}
        base = sum(task_milestones.get(name, 0) for name in self.milestones_achieved)

        # Elegance bonus
        elegance = self._elegance_bonus()

        # Noise penalty
        noise_penalty = self._noise_penalty()

        raw = base + elegance - noise_penalty
        return min(1.0, max(0.0, round(raw, 4)))

    def _elegance_bonus(self) -> float:
        """Calculate elegance bonus based on step efficiency."""
        if self.total_steps == 0 or "flag_captured" not in self.milestones_achieved:
            return 0.0

        ratio = self.total_steps / self.task.optimal_steps
        if ratio <= 1.5:
            return 0.10
        elif ratio <= 3.0:
            return 0.05
        elif ratio <= 5.0:
            return 0.0
        else:
            return -0.05

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
