"""
Data models for flag candidates and analysis results.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AnalysisMethod(Enum):
    """Source of flag candidate extraction."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    SYMBOLIC = "symbolic"


@dataclass
class FlagCandidate:
    """Represents a flag candidate with metadata."""
    candidate: str
    score: float
    method: AnalysisMethod
    source: str  # e.g., "ltrace strcmp @ main+0x123"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "candidate": self.candidate,
            "score": self.score,
            "source": self.source,
            "analysis_method": self.method.value
        }
    
    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"{self.candidate} (score={self.score:.1f}, {self.method.value})"

