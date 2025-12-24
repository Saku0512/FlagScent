"""
Tests for data models.
"""

import pytest
from flagscent.models import FlagCandidate, AnalysisMethod


class TestAnalysisMethod:
    """Tests for AnalysisMethod enum."""
    
    def test_enum_values(self):
        """Test that enum has expected values."""
        assert AnalysisMethod.STATIC.value == "static"
        assert AnalysisMethod.DYNAMIC.value == "dynamic"
        assert AnalysisMethod.SYMBOLIC.value == "symbolic"


class TestFlagCandidate:
    """Tests for FlagCandidate dataclass."""
    
    def test_creation(self):
        """Test creating a FlagCandidate."""
        candidate = FlagCandidate(
            candidate="CTF{test}",
            score=85.5,
            method=AnalysisMethod.DYNAMIC,
            source="ltrace strcmp"
        )
        
        assert candidate.candidate == "CTF{test}"
        assert candidate.score == 85.5
        assert candidate.method == AnalysisMethod.DYNAMIC
        assert candidate.source == "ltrace strcmp"
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        candidate = FlagCandidate(
            candidate="CTF{test}",
            score=85.5,
            method=AnalysisMethod.STATIC,
            source="static string extraction"
        )
        
        result = candidate.to_dict()
        
        assert result["candidate"] == "CTF{test}"
        assert result["score"] == 85.5
        assert result["source"] == "static string extraction"
        assert result["analysis_method"] == "static"
    
    def test_str_representation(self):
        """Test string representation."""
        candidate = FlagCandidate(
            candidate="CTF{test}",
            score=92.3,
            method=AnalysisMethod.DYNAMIC,
            source="ltrace"
        )
        
        result = str(candidate)
        
        assert "CTF{test}" in result
        assert "92.3" in result
        assert "dynamic" in result

