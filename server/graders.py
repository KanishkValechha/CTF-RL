"""
Deterministic graders for CTF tasks.
"""

from __future__ import annotations

from models import GradeSummaryModel

from .reward import RewardTracker
from .tasks.base_task import BaseTask


class TaskGrader:
    """
    Deterministic grader for a task episode.
    """

    def __init__(self, task: BaseTask):
        self.task = task

    def grade(self, tracker: RewardTracker) -> float:
        """Return a normalized final score between 0.0 and 1.0."""
        return tracker.calculate_reward()

    def grade_summary(self, tracker: RewardTracker) -> dict:
        """Return a structured score breakdown."""
        score = self.grade(tracker)
        milestones_hit = sorted(tracker.milestones_achieved)
        task_milestone_names = [milestone.name for milestone in self.task.milestones]

        summary = GradeSummaryModel(
            task=self.task.name,
            difficulty=self.task.difficulty,
            final_score=score,
            flag_captured="flag_captured" in tracker.milestones_achieved,
            milestones_achieved=milestones_hit,
            milestones_missed=[name for name in task_milestone_names if name not in milestones_hit],
            total_steps=tracker.total_steps,
            optimal_steps=self.task.optimal_steps,
            noise_count=tracker.noise_count,
            elegance_bonus=tracker._precision_bonus(),
            precision_bonus=tracker._precision_bonus(),
            noise_penalty=tracker._noise_penalty(),
            detection_risk=tracker.detection_risk(),
        )
        return summary.model_dump()
