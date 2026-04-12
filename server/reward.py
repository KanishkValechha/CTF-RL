"""
Reward tracking, precision accounting, and deterministic noise analysis.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .tasks.base_task import BaseTask, MilestoneContext


class NoiseDetector:
    """
    Detect unproductive probing that should reduce the perceived precision
    of an attack trajectory.
    """

    def __init__(self):
        self.endpoint_hits: Counter[str] = Counter()
        self.payload_hashes: Counter[int] = Counter()
        self.progress_checkpoints: list[int] = [0]

    def reset(self):
        """Reset noise detection state."""
        self.endpoint_hits.clear()
        self.payload_hashes.clear()
        self.progress_checkpoints = [0]

    def is_noise(self, action_name: str, action_args: dict, current_milestone_count: int) -> bool:
        """Return True when an action looks like low-signal probing."""
        if action_name != "http_request":
            return False

        path = action_args.get("path", "")
        method = str(action_args.get("method", "GET")).upper()
        endpoint_key = f"{method} {path}"
        self.endpoint_hits[endpoint_key] += 1

        if self.endpoint_hits[endpoint_key] > 5 and current_milestone_count <= self.progress_checkpoints[-1]:
            return True

        payload_hash = hash(str(sorted(action_args.items())))
        self.payload_hashes[payload_hash] += 1
        if self.payload_hashes[payload_hash] > 2:
            return True

        body = str(action_args.get("body", ""))
        if len(body) > 1000:
            return True

        self.progress_checkpoints.append(current_milestone_count)
        return False


class RewardTracker:
    """
    Track milestone progress, precision, and deterministic score shaping.
    """

    def __init__(self, task: BaseTask):
        self.task = task
        self.milestones_achieved: set[str] = set()
        self.total_steps: int = 0
        self.noise_count: int = 0
        self.source_files_read: set[str] = set()
        self.endpoints_hit: Counter[str] = Counter()
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
        """
        self.total_steps += 1
        previous_reward = self.calculate_reward()

        if self.noise_detector.is_noise(action_name, action_args, len(self.milestones_achieved)):
            self.noise_count += 1

        if action_name == "view_source":
            file_path = action_args.get("file_path", "")
            if file_path:
                self.source_files_read.add(str(file_path))

        if action_name == "http_request":
            path = str(action_args.get("path", ""))
            method = str(action_args.get("method", "GET")).upper()
            self.endpoints_hit[f"{method} {path}"] += 1

        context = MilestoneContext(
            action_name=action_name,
            action_args=action_args or {},
            result=result if isinstance(result, dict) else {"body": result},
            total_steps=self.total_steps,
            source_files_read=frozenset(self.source_files_read),
            endpoints_hit=dict(self.endpoints_hit),
            milestones_achieved=frozenset(self.milestones_achieved),
        )
        self.milestones_achieved.update(self.task.evaluate_milestones(context))

        current_reward = self.calculate_reward()
        diff = current_reward - previous_reward
        self._last_reward = current_reward
        return diff

    def achieve_milestone(self, name: str):
        """Manually mark a milestone as achieved."""
        self.milestones_achieved.add(name)

    def calculate_reward(self) -> float:
        """
        Calculate current cumulative reward in the normalized range [0.0, 1.0].
        """
        task_milestones = {milestone.name: milestone.reward_value for milestone in self.task.milestones}
        base_reward = sum(task_milestones.get(name, 0.0) for name in self.milestones_achieved)
        precision_bonus = self._precision_bonus()
        noise_penalty = self._noise_penalty()
        raw_reward = base_reward + precision_bonus - noise_penalty
        return min(1.0, max(0.0, round(raw_reward, 4)))

    def _precision_bonus(self) -> float:
        """Reward shorter, more surgical trajectories after a full solve."""
        if self.total_steps == 0 or "flag_captured" not in self.milestones_achieved:
            return 0.0

        ratio = self.total_steps / max(self.task.optimal_steps, 1)
        if ratio <= 1.5:
            return 0.10
        if ratio <= 3.0:
            return 0.05
        if ratio <= 5.0:
            return 0.0
        return -0.05

    def _noise_penalty(self) -> float:
        """Soft penalty for repeated, low-signal actions."""
        if self.total_steps == 0:
            return 0.0
        noise_ratio = self.noise_count / max(self.total_steps, 1)
        return min(0.2, round(noise_ratio * 0.3, 4))

    def detection_risk(self) -> float:
        """A deterministic summary metric for how noisy the trajectory looked."""
        if self.total_steps == 0:
            return 0.0

        repeated_hits = sum(max(0, count - 2) for count in self.endpoints_hit.values())
        repeat_ratio = repeated_hits / max(self.total_steps, 1)
        noise_ratio = self.noise_count / max(self.total_steps, 1)
        overstep_ratio = max(0.0, self.total_steps - self.task.optimal_steps) / max(self.task.optimal_steps, 1)

        risk = (noise_ratio * 0.6) + (repeat_ratio * 0.2) + (overstep_ratio * 0.2)
        return min(1.0, max(0.0, round(risk, 4)))

    def get_summary(self) -> dict:
        """Get a summary of the current tracker state."""
        return {
            "milestones_achieved": sorted(self.milestones_achieved),
            "total_milestones": len(self.task.milestones),
            "total_steps": self.total_steps,
            "noise_count": self.noise_count,
            "current_reward": self.calculate_reward(),
            "precision_bonus": self._precision_bonus(),
            "noise_penalty": self._noise_penalty(),
            "detection_risk": self.detection_risk(),
            "source_files_read": sorted(self.source_files_read),
        }
