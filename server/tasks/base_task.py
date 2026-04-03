"""
Base task definition.

Provides the dataclass that all CTF tasks inherit from.
"""

from dataclasses import dataclass, field


@dataclass
class Milestone:
    """A progress milestone that triggers partial reward."""

    name: str
    description: str
    reward_value: float


@dataclass
class BaseTask:
    """Base class for CTF task definitions."""

    name: str
    display_name: str
    description: str
    difficulty: str  # "easy", "medium", "hard"
    flag: str
    optimal_steps: int
    relevant_files: list[str] = field(default_factory=list)
    vulnerable_endpoints: list[str] = field(default_factory=list)
    milestones: list[Milestone] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for observation metadata."""
        return {
            "task_name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "difficulty": self.difficulty,
            "optimal_steps": self.optimal_steps,
            "hints": self.hints[:1],  # Only first hint initially
        }
