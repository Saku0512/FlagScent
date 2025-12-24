"""
Scoring and ranking system for flag candidates.
"""

from typing import List
from flagscent.models import FlagCandidate, AnalysisMethod
from flagscent.heuristic import calculate_heuristic_score


def calculate_source_confidence_bonus(method: AnalysisMethod) -> float:
    """
    Calculate confidence bonus based on extraction method.
    
    Higher confidence: trace > symbolic > static
    """
    bonuses = {
        AnalysisMethod.DYNAMIC: 10.0,  # Highest confidence
        AnalysisMethod.SYMBOLIC: 5.0,
        AnalysisMethod.STATIC: 0.0,   # Base confidence
    }
    return bonuses.get(method, 0.0)


def score_candidate(candidate: str, method: AnalysisMethod, source: str) -> FlagCandidate:
    """
    Calculate total score for a flag candidate.
    
    Args:
        candidate: The candidate string
        method: Extraction method
        source: Source description
    
    Returns:
        FlagCandidate with calculated score
    """
    # Base heuristic score
    heuristic_score, breakdown = calculate_heuristic_score(candidate)
    
    # Add source confidence bonus
    confidence_bonus = calculate_source_confidence_bonus(method)
    
    total_score = heuristic_score + confidence_bonus
    
    return FlagCandidate(
        candidate=candidate,
        score=total_score,
        method=method,
        source=source
    )


def rank_candidates(candidates: List[FlagCandidate]) -> List[FlagCandidate]:
    """
    Rank candidates by score in descending order.
    
    Args:
        candidates: List of flag candidates
    
    Returns:
        Sorted list (highest score first)
    """
    return sorted(candidates, key=lambda c: c.score, reverse=True)

