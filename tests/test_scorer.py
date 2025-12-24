"""
Tests for scoring and ranking system.
"""

import pytest
from flagscent.models import FlagCandidate, AnalysisMethod
from flagscent.scorer import (
    calculate_source_confidence_bonus,
    score_candidate,
    rank_candidates
)


class TestCalculateSourceConfidenceBonus:
    """Tests for source confidence bonus calculation."""
    
    def test_dynamic_bonus(self):
        """Test dynamic method has highest bonus."""
        bonus = calculate_source_confidence_bonus(AnalysisMethod.DYNAMIC)
        assert bonus == 10.0
    
    def test_symbolic_bonus(self):
        """Test symbolic method has medium bonus."""
        bonus = calculate_source_confidence_bonus(AnalysisMethod.SYMBOLIC)
        assert bonus == 5.0
    
    def test_static_bonus(self):
        """Test static method has no bonus."""
        bonus = calculate_source_confidence_bonus(AnalysisMethod.STATIC)
        assert bonus == 0.0
    
    def test_bonus_ordering(self):
        """Test that bonuses are ordered correctly."""
        dynamic_bonus = calculate_source_confidence_bonus(AnalysisMethod.DYNAMIC)
        symbolic_bonus = calculate_source_confidence_bonus(AnalysisMethod.SYMBOLIC)
        static_bonus = calculate_source_confidence_bonus(AnalysisMethod.STATIC)
        
        assert dynamic_bonus > symbolic_bonus
        assert symbolic_bonus > static_bonus


class TestScoreCandidate:
    """Tests for candidate scoring."""
    
    def test_score_perfect_flag_dynamic(self):
        """Test scoring perfect flag from dynamic source."""
        candidate = score_candidate(
            "CTF{rev_is_fun_2024}",
            AnalysisMethod.DYNAMIC,
            "ltrace strcmp"
        )
        
        assert candidate.candidate == "CTF{rev_is_fun_2024}"
        assert candidate.method == AnalysisMethod.DYNAMIC
        assert candidate.source == "ltrace strcmp"
        # Should have high score (heuristic + dynamic bonus)
        assert candidate.score > 80.0
    
    def test_score_perfect_flag_static(self):
        """Test scoring perfect flag from static source."""
        candidate = score_candidate(
            "CTF{rev_is_fun_2024}",
            AnalysisMethod.STATIC,
            "static string extraction"
        )
        
        # Should have lower score than dynamic (no bonus)
        assert candidate.score > 70.0
        assert candidate.method == AnalysisMethod.STATIC
    
    def test_score_includes_confidence_bonus(self):
        """Test that score includes confidence bonus."""
        same_flag = "CTF{test_flag_123}"
        
        dynamic_candidate = score_candidate(
            same_flag,
            AnalysisMethod.DYNAMIC,
            "dynamic"
        )
        
        static_candidate = score_candidate(
            same_flag,
            AnalysisMethod.STATIC,
            "static"
        )
        
        # Dynamic should have higher score due to bonus
        assert dynamic_candidate.score > static_candidate.score
        score_diff = dynamic_candidate.score - static_candidate.score
        # Difference should be approximately the bonus (10.0)
        assert abs(score_diff - 10.0) < 0.1
    
    def test_score_poor_candidate(self):
        """Test scoring of poor candidate."""
        candidate = score_candidate(
            "not_a_flag",
            AnalysisMethod.DYNAMIC,
            "test"
        )
        
        # Should have lower score than perfect flags
        # not_a_flag gets 55.0 (heuristic) + 10.0 (dynamic bonus) = 65.0
        # This is lower than a perfect flag (100+10=110)
        assert candidate.score < 100.0
        
        # Compare with static method (no bonus)
        static_candidate = score_candidate(
            "not_a_flag",
            AnalysisMethod.STATIC,
            "test"
        )
        # Dynamic should have higher score due to bonus
        assert candidate.score > static_candidate.score


class TestRankCandidates:
    """Tests for candidate ranking."""
    
    def test_rank_by_score_descending(self):
        """Test that candidates are ranked by score descending."""
        candidates = [
            FlagCandidate("low", 10.0, AnalysisMethod.STATIC, "test"),
            FlagCandidate("high", 90.0, AnalysisMethod.DYNAMIC, "test"),
            FlagCandidate("medium", 50.0, AnalysisMethod.SYMBOLIC, "test"),
        ]
        
        ranked = rank_candidates(candidates)
        
        assert ranked[0].score == 90.0
        assert ranked[1].score == 50.0
        assert ranked[2].score == 10.0
    
    def test_rank_empty_list(self):
        """Test ranking empty list."""
        ranked = rank_candidates([])
        assert ranked == []
    
    def test_rank_single_candidate(self):
        """Test ranking single candidate."""
        candidates = [
            FlagCandidate("test", 85.0, AnalysisMethod.DYNAMIC, "test")
        ]
        
        ranked = rank_candidates(candidates)
        assert len(ranked) == 1
        assert ranked[0].candidate == "test"
    
    def test_rank_same_scores(self):
        """Test ranking candidates with same scores."""
        candidates = [
            FlagCandidate("a", 50.0, AnalysisMethod.STATIC, "test"),
            FlagCandidate("b", 50.0, AnalysisMethod.STATIC, "test"),
            FlagCandidate("c", 50.0, AnalysisMethod.STATIC, "test"),
        ]
        
        ranked = rank_candidates(candidates)
        # Should maintain order (stable sort)
        assert len(ranked) == 3
        assert all(c.score == 50.0 for c in ranked)
    
    def test_rank_realistic_scenario(self):
        """Test ranking with realistic flag candidates."""
        candidates = [
            score_candidate("CTF{perfect_flag}", AnalysisMethod.DYNAMIC, "ltrace"),
            score_candidate("flag{good_flag}", AnalysisMethod.SYMBOLIC, "angr"),
            score_candidate("not_a_flag", AnalysisMethod.STATIC, "strings"),
            score_candidate("CTF{another_good}", AnalysisMethod.STATIC, "strings"),
        ]
        
        ranked = rank_candidates(candidates)
        
        # Should be sorted by score
        for i in range(len(ranked) - 1):
            assert ranked[i].score >= ranked[i + 1].score
        
        # Best candidate should be at top
        assert ranked[0].candidate.startswith("CTF{") or ranked[0].candidate.startswith("flag{")

