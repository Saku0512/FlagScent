"""
Heuristic analysis for flag candidate validation and scoring.
"""

import string
import math
from typing import List, Tuple


# Common CTF flag prefixes
FLAG_PREFIXES = ["CTF{", "flag{", "FLAG{", "ctf{", "Flag{"]


def detect_flag_prefix(candidate: str) -> Tuple[bool, str]:
    """
    Detect if candidate starts with a known flag prefix.
    
    Returns:
        (is_prefix_match, matched_prefix)
    """
    for prefix in FLAG_PREFIXES:
        if candidate.startswith(prefix):
            return True, prefix
    return False, ""


def calculate_printability_ratio(candidate: str) -> float:
    """
    Calculate ratio of printable characters.
    
    Returns:
        Ratio between 0.0 and 1.0
    """
    if not candidate:
        return 0.0
    
    printable_count = sum(1 for c in candidate if c.isprintable())
    return printable_count / len(candidate)


def estimate_entropy(candidate: str) -> float:
    """
    Estimate Shannon entropy of the string.
    
    Returns:
        Entropy value (bits per character)
    """
    if not candidate:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in candidate:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    length = len(candidate)
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def validate_bracket_balance(candidate: str) -> bool:
    """
    Validate bracket balance (for CTF{...} format).
    
    Returns:
        True if brackets are balanced
    """
    stack = []
    bracket_pairs = {"{": "}", "[": "]", "(": ")"}
    
    for char in candidate:
        if char in bracket_pairs:
            stack.append(char)
        elif char in bracket_pairs.values():
            if not stack:
                return False
            opening = stack.pop()
            if bracket_pairs[opening] != char:
                return False
    
    return len(stack) == 0


def validate_length(candidate: str, min_length: int = 15, max_length: int = 80) -> bool:
    """
    Validate candidate length is within reasonable range.
    
    Args:
        candidate: String to validate
        min_length: Minimum acceptable length
        max_length: Maximum acceptable length
    
    Returns:
        True if length is within range
    """
    return min_length <= len(candidate) <= max_length


def calculate_heuristic_score(candidate: str) -> Tuple[float, dict]:
    """
    Calculate comprehensive heuristic score for a candidate.
    
    Returns:
        (total_score, score_breakdown)
    """
    breakdown = {}
    
    # Prefix match (0-30 points)
    has_prefix, matched_prefix = detect_flag_prefix(candidate)
    prefix_score = 30.0 if has_prefix else 0.0
    breakdown["prefix"] = prefix_score
    
    # Printability (0-25 points)
    printability = calculate_printability_ratio(candidate)
    printability_score = printability * 25.0
    breakdown["printability"] = printability_score
    
    # Entropy (0-20 points)
    # Good flags have moderate entropy (not too low, not too high)
    entropy = estimate_entropy(candidate)
    # Ideal entropy range: 3.0-5.0 bits per char
    if 3.0 <= entropy <= 5.0:
        entropy_score = 20.0
    elif 2.0 <= entropy < 3.0 or 5.0 < entropy <= 6.0:
        entropy_score = 15.0
    elif 1.0 <= entropy < 2.0 or 6.0 < entropy <= 7.0:
        entropy_score = 10.0
    else:
        entropy_score = 5.0
    breakdown["entropy"] = entropy_score
    
    # Bracket balance (0-15 points)
    bracket_score = 15.0 if validate_bracket_balance(candidate) else 0.0
    breakdown["brackets"] = bracket_score
    
    # Length validation (0-10 points)
    length_score = 10.0 if validate_length(candidate) else 0.0
    breakdown["length"] = length_score
    
    total_score = sum(breakdown.values())
    return total_score, breakdown

