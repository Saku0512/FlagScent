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


def calculate_consistency_bonus(candidate: FlagCandidate, all_candidates: List[FlagCandidate]) -> float:
    """
    Calculate bonus based on consistency with other candidates.
    
    Args:
        candidate: Candidate to score
        all_candidates: All other candidates for comparison
    
    Returns:
        Consistency bonus score
    """
    bonus = 0.0
    cand_str = candidate.candidate
    
    # Check for prefix matches with other candidates
    for other in all_candidates:
        if other.candidate == cand_str:
            continue
        
        other_str = other.candidate
        
        # Prefix match bonus
        if cand_str.startswith("CTF{") and other_str.startswith("CTF{"):
            bonus += 5.0
        elif cand_str.startswith("flag{") and other_str.startswith("flag{"):
            bonus += 5.0
        
        # Common substring bonus
        if len(cand_str) > 10 and len(other_str) > 10:
            # Find longest common substring
            common_len = _longest_common_substring_length(cand_str, other_str)
            if common_len >= 5:
                bonus += min(common_len * 2.0, 20.0)
    
    return min(bonus, 30.0)  # Cap at 30 points


def _longest_common_substring_length(s1: str, s2: str) -> int:
    """Find length of longest common substring."""
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    max_len = 0
    
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i-1] == s2[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
                max_len = max(max_len, dp[i][j])
    
    return max_len


def score_candidate(candidate: str, method: AnalysisMethod, source: str, 
                   all_candidates: List[FlagCandidate] = None) -> FlagCandidate:
    """
    Calculate total score for a flag candidate.
    
    Args:
        candidate: The candidate string
        method: Extraction method
        source: Source description
        all_candidates: Optional list of all candidates for consistency scoring
    
    Returns:
        FlagCandidate with calculated score
    """
    # Base heuristic score
    heuristic_score, breakdown = calculate_heuristic_score(candidate)
    
    # Add source confidence bonus
    confidence_bonus = calculate_source_confidence_bonus(method)
    
    total_score = heuristic_score + confidence_bonus
    
    # Add consistency bonus if other candidates are provided
    if all_candidates:
        consistency_bonus = calculate_consistency_bonus(
            FlagCandidate(candidate, total_score, method, source),
            all_candidates
        )
        total_score += consistency_bonus
    
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

