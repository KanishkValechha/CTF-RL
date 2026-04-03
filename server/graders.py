"""
Graders for CTF tasks.

Each grader produces a deterministic 0.0-1.0 score based on the
agent's episode performance.
"""

from .reward import RewardTracker
from .tasks.base_task import BaseTask


class TaskGrader:
    """
    Deterministic grader for a CTF task.

    Takes the RewardTracker state at the end of an episode
    and produces a final score between 0.0 and 1.0.
    """

    def __init__(self, task: BaseTask):
        self.task = task

    def grade(self, tracker: RewardTracker) -> float:
        """
        Grade a completed episode.

        Args:
            tracker: The RewardTracker with episode state.

        Returns:
            Score between 0.0 and 1.0.
        """
        return tracker.calculate_reward()

    def grade_summary(self, tracker: RewardTracker) -> dict:
        """
        Produce a detailed grading summary.

        Args:
            tracker: The RewardTracker with episode state.

        Returns:
            Dictionary with score breakdown.
        """
        score = self.grade(tracker)
        milestones_hit = sorted(tracker.milestones_achieved)
        task_milestone_names = [m.name for m in self.task.milestones]

        return {
            "task": self.task.name,
            "difficulty": self.task.difficulty,
            "final_score": score,
            "flag_captured": "flag_captured" in tracker.milestones_achieved,
            "milestones_achieved": milestones_hit,
            "milestones_missed": [m for m in task_milestone_names if m not in milestones_hit],
            "total_steps": tracker.total_steps,
            "optimal_steps": self.task.optimal_steps,
            "noise_count": tracker.noise_count,
            "elegance_bonus": tracker._elegance_bonus(),
            "noise_penalty": tracker._noise_penalty(),
        }
