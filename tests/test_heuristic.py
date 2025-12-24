"""
Tests for heuristic analysis functions.
"""

import pytest
from flagscent.heuristic import (
    detect_flag_prefix,
    calculate_printability_ratio,
    estimate_entropy,
    validate_bracket_balance,
    validate_length,
    calculate_heuristic_score,
    FLAG_PREFIXES
)


class TestDetectFlagPrefix:
    """Tests for flag prefix detection."""
    
    def test_ctf_prefix_uppercase(self):
        """Test detection of CTF{ prefix."""
        has_prefix, matched = detect_flag_prefix("CTF{test_flag}")
        assert has_prefix is True
        assert matched == "CTF{"
    
    def test_flag_prefix_lowercase(self):
        """Test detection of flag{ prefix."""
        has_prefix, matched = detect_flag_prefix("flag{test_flag}")
        assert has_prefix is True
        assert matched == "flag{"
    
    def test_no_prefix(self):
        """Test string without flag prefix."""
        has_prefix, matched = detect_flag_prefix("not_a_flag")
        assert has_prefix is False
        assert matched == ""
    
    def test_all_prefixes(self):
        """Test all known prefixes."""
        for prefix in FLAG_PREFIXES:
            test_string = prefix + "test}"
            has_prefix, matched = detect_flag_prefix(test_string)
            assert has_prefix is True
            assert matched == prefix
    
    def test_prefix_in_middle(self):
        """Test that prefix must be at start."""
        has_prefix, matched = detect_flag_prefix("some_text_CTF{test}")
        assert has_prefix is False


class TestCalculatePrintabilityRatio:
    """Tests for printability ratio calculation."""
    
    def test_all_printable(self):
        """Test string with all printable characters."""
        ratio = calculate_printability_ratio("CTF{test_flag}")
        assert ratio == 1.0
    
    def test_empty_string(self):
        """Test empty string."""
        ratio = calculate_printability_ratio("")
        assert ratio == 0.0
    
    def test_mixed_characters(self):
        """Test string with non-printable characters."""
        # Contains newline and tab
        ratio = calculate_printability_ratio("CTF{test\n\tflag}")
        assert 0.0 < ratio < 1.0
    
    def test_unicode_printable(self):
        """Test unicode printable characters."""
        ratio = calculate_printability_ratio("CTF{日本語}")
        assert ratio == 1.0


class TestEstimateEntropy:
    """Tests for entropy estimation."""
    
    def test_empty_string(self):
        """Test empty string has zero entropy."""
        entropy = estimate_entropy("")
        assert entropy == 0.0
    
    def test_single_character(self):
        """Test single character has zero entropy."""
        entropy = estimate_entropy("a")
        assert entropy == 0.0
    
    def test_repeated_characters(self):
        """Test repeated characters have low entropy."""
        entropy = estimate_entropy("aaaaa")
        assert entropy < 1.0
    
    def test_diverse_characters(self):
        """Test diverse characters have higher entropy."""
        entropy_diverse = estimate_entropy("CTF{abc123XYZ!@#}")
        entropy_repeated = estimate_entropy("aaaaaaaaaaaaaaa")
        assert entropy_diverse > entropy_repeated
    
    def test_typical_flag_entropy(self):
        """Test typical flag has moderate entropy."""
        entropy = estimate_entropy("CTF{rev_is_fun_2024}")
        # Typical flags should have entropy between 2-6 bits per char
        assert 2.0 <= entropy <= 6.0


class TestValidateBracketBalance:
    """Tests for bracket balance validation."""
    
    def test_balanced_curly_braces(self):
        """Test balanced curly braces."""
        assert validate_bracket_balance("CTF{test}") is True
    
    def test_unbalanced_curly_braces(self):
        """Test unbalanced curly braces."""
        assert validate_bracket_balance("CTF{test") is False
        assert validate_bracket_balance("CTFtest}") is False
    
    def test_nested_balanced(self):
        """Test nested balanced brackets."""
        assert validate_bracket_balance("CTF{test{inner}}") is True
    
    def test_mixed_brackets(self):
        """Test mixed bracket types."""
        assert validate_bracket_balance("CTF{test[inner]}") is True
        assert validate_bracket_balance("CTF{test[inner}") is False
    
    def test_no_brackets(self):
        """Test string without brackets."""
        assert validate_bracket_balance("no_brackets_here") is True
    
    def test_wrong_order(self):
        """Test brackets in wrong order."""
        assert validate_bracket_balance("CTF}test{") is False


class TestValidateLength:
    """Tests for length validation."""
    
    def test_valid_length(self):
        """Test string within valid length range."""
        assert validate_length("CTF{valid_length_flag}") is True
    
    def test_too_short(self):
        """Test string too short."""
        assert validate_length("CTF{short}") is False
    
    def test_too_long(self):
        """Test string too long."""
        long_string = "CTF{" + "a" * 100 + "}"
        assert validate_length(long_string) is False
    
    def test_minimum_length(self):
        """Test string at minimum length."""
        min_string = "a" * 15
        assert validate_length(min_string) is True
    
    def test_maximum_length(self):
        """Test string at maximum length."""
        max_string = "a" * 80
        assert validate_length(max_string) is True
    
    def test_custom_length_range(self):
        """Test custom length range."""
        assert validate_length("test", min_length=3, max_length=10) is True
        assert validate_length("te", min_length=3, max_length=10) is False


class TestCalculateHeuristicScore:
    """Tests for comprehensive heuristic scoring."""
    
    def test_perfect_flag(self):
        """Test scoring of a perfect flag candidate."""
        candidate = "CTF{rev_is_fun_2024}"
        score, breakdown = calculate_heuristic_score(candidate)
        
        # Should have high score
        assert score > 70.0
        
        # Check breakdown components
        assert "prefix" in breakdown
        assert "printability" in breakdown
        assert "entropy" in breakdown
        assert "brackets" in breakdown
        assert "length" in breakdown
        
        # Perfect flag should have prefix score
        assert breakdown["prefix"] == 30.0
    
    def test_no_prefix_flag(self):
        """Test scoring of flag without prefix."""
        candidate = "just_a_regular_string_here"
        score, breakdown = calculate_heuristic_score(candidate)
        
        # Should have lower score due to no prefix
        assert breakdown["prefix"] == 0.0
        # This string gets 70.0 (25 printability + 20 entropy + 15 brackets + 10 length)
        assert score <= 70.0
    
    def test_unbalanced_brackets(self):
        """Test scoring of flag with unbalanced brackets."""
        candidate = "CTF{unbalanced"
        score, breakdown = calculate_heuristic_score(candidate)
        
        assert breakdown["brackets"] == 0.0
    
    def test_too_short(self):
        """Test scoring of too short candidate."""
        candidate = "CTF{short}"
        score, breakdown = calculate_heuristic_score(candidate)
        
        assert breakdown["length"] == 0.0
    
    def test_score_components_sum(self):
        """Test that score equals sum of components."""
        candidate = "CTF{test_flag_123}"
        score, breakdown = calculate_heuristic_score(candidate)
        
        calculated_sum = sum(breakdown.values())
        assert abs(score - calculated_sum) < 0.01  # Allow floating point error
    
    def test_different_flags_ranked(self):
        """Test that better flags get higher scores."""
        good_flag = "CTF{rev_is_fun_2024}"
        bad_flag = "not_a_flag"
        
        good_score, _ = calculate_heuristic_score(good_flag)
        bad_score, _ = calculate_heuristic_score(bad_flag)
        
        assert good_score > bad_score

