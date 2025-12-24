"""
Candidate merging module for combining partial flag candidates.
"""

from typing import List, Tuple, Optional
from flagscent.models import FlagCandidate, AnalysisMethod


class CandidateMerger:
    """Merge partial flag candidates into complete flags."""
    
    def __init__(self):
        """Initialize candidate merger."""
        pass
    
    def find_prefix_suffix_matches(self, candidates: List[FlagCandidate]) -> List[FlagCandidate]:
        """
        Find and merge candidates with matching prefix/suffix.
        
        Examples:
        - "CTF{rev_" (ltrace) + "is_fun}" (strings) → "CTF{rev_is_fun}"
        - "flag{test" + "_123}" → "flag{test_123}"
        
        Args:
            candidates: List of flag candidates
        
        Returns:
            List of merged candidates (original + merged)
        """
        merged = []
        seen = set()
        
        # Group candidates by prefix
        prefix_candidates = {}  # prefix -> list of candidates
        suffix_candidates = {}  # suffix -> list of candidates
        
        for candidate in candidates:
            cand_str = candidate.candidate
            if cand_str in seen:
                continue
            seen.add(cand_str)
            
            # Check for common flag prefixes
            for prefix in ["CTF{", "flag{", "FLAG{", "ctf{", "Flag{", "Alpaca{", "alpaca{"]:
                if cand_str.startswith(prefix) and not cand_str.endswith("}"):
                    # This looks like a prefix-only candidate
                    if prefix not in prefix_candidates:
                        prefix_candidates[prefix] = []
                    prefix_candidates[prefix].append(candidate)
                    break
            
            # Check for suffix (ends with } but doesn't start with prefix)
            if cand_str.endswith("}") and not any(cand_str.startswith(p) for p in ["CTF{", "flag{", "FLAG{", "ctf{", "Flag{", "Alpaca{", "alpaca{"]):
                # Extract potential suffix part
                # Look for pattern like "something}" where something might be part of flag
                if "{" in cand_str:
                    # Already has opening brace, might be complete
                    continue
                # Try to find what prefix this might belong to
                # For now, store as suffix candidate
                suffix_key = cand_str[-20:] if len(cand_str) > 20 else cand_str
                if suffix_key not in suffix_candidates:
                    suffix_candidates[suffix_key] = []
                suffix_candidates[suffix_key].append(candidate)
        
        # Try to merge prefix + suffix
        for prefix, prefix_list in prefix_candidates.items():
            for prefix_cand in prefix_list:
                prefix_str = prefix_cand.candidate
                
                # Look for matching suffixes
                for suffix_key, suffix_list in suffix_candidates.items():
                    for suffix_cand in suffix_list:
                        suffix_str = suffix_cand.candidate
                        
                        # Try merging
                        merged_str = self._try_merge(prefix_str, suffix_str)
                        if merged_str and merged_str not in seen:
                            seen.add(merged_str)
                            # Create merged candidate with combined score
                            merged_score = (prefix_cand.score + suffix_cand.score) * 0.6  # Slight penalty for merging
                            merged_score += 30.0  # Bonus for successful merge
                            
                            # Determine method (prefer dynamic if either is dynamic)
                            method = prefix_cand.method
                            if suffix_cand.method == AnalysisMethod.DYNAMIC:
                                method = AnalysisMethod.DYNAMIC
                            elif suffix_cand.method == AnalysisMethod.SYMBOLIC and method != AnalysisMethod.DYNAMIC:
                                method = AnalysisMethod.SYMBOLIC
                            
                            merged_candidate = FlagCandidate(
                                candidate=merged_str,
                                score=merged_score,
                                method=method,
                                source=f"merged: {prefix_cand.source} + {suffix_cand.source}"
                            )
                            merged.append(merged_candidate)
        
        return merged
    
    def _try_merge(self, prefix_str: str, suffix_str: str) -> Optional[str]:
        """
        Try to merge prefix and suffix strings.
        
        Args:
            prefix_str: Prefix string (e.g., "CTF{rev_")
            suffix_str: Suffix string (e.g., "is_fun}")
        
        Returns:
            Merged string if successful, None otherwise
        """
        # Remove closing brace from prefix if present
        prefix_clean = prefix_str.rstrip("}")
        
        # Remove opening prefix from suffix if present
        suffix_clean = suffix_str
        for p in ["CTF{", "flag{", "FLAG{", "ctf{", "Flag{", "Alpaca{", "alpaca{"]:
            if suffix_clean.startswith(p):
                suffix_clean = suffix_clean[len(p):]
                break
        
        # Check if they can be merged
        # Prefix should end with { or _ or similar
        # Suffix should start with alphanumeric or }
        
        # Simple merge: prefix + suffix
        if prefix_clean.endswith("{") or prefix_clean.endswith("_") or prefix_clean.endswith("-"):
            if suffix_clean.startswith("}") or suffix_clean[0].isalnum() if suffix_clean else False:
                merged = prefix_clean + suffix_clean
                # Ensure it has proper flag format
                if "{" in merged and "}" in merged:
                    return merged
        
        # Try overlap matching (common subsequence)
        overlap = self._find_overlap(prefix_clean, suffix_clean)
        if overlap:
            # Remove overlap from one side
            if prefix_clean.endswith(overlap):
                merged = prefix_clean + suffix_clean[len(overlap):]
            elif suffix_clean.startswith(overlap):
                merged = prefix_clean[:-len(overlap)] + suffix_clean
            else:
                merged = prefix_clean + suffix_clean
            
            if "{" in merged and "}" in merged:
                return merged
        
        return None
    
    def _find_overlap(self, str1: str, str2: str, min_overlap: int = 3) -> Optional[str]:
        """
        Find common overlap between two strings.
        
        Args:
            str1: First string
            str2: Second string
            min_overlap: Minimum overlap length
        
        Returns:
            Overlap string if found, None otherwise
        """
        # Check if end of str1 matches start of str2
        for i in range(min_overlap, min(len(str1), len(str2)) + 1):
            if str1[-i:] == str2[:i]:
                return str1[-i:]
        
        return None
    
    def find_common_subsequence_merges(self, candidates: List[FlagCandidate]) -> List[FlagCandidate]:
        """
        Find candidates that can be merged based on common subsequences.
        
        Args:
            candidates: List of flag candidates
        
        Returns:
            List of merged candidates
        """
        merged = []
        seen = set(c.candidate for c in candidates)
        
        # Simple approach: look for candidates that share common parts
        for i, cand1 in enumerate(candidates):
            for cand2 in candidates[i+1:]:
                merged_str = self._try_merge(cand1.candidate, cand2.candidate)
                if merged_str and merged_str not in seen:
                    seen.add(merged_str)
                    merged_score = (cand1.score + cand2.score) * 0.6 + 30.0
                    
                    method = cand1.method
                    if cand2.method == AnalysisMethod.DYNAMIC:
                        method = AnalysisMethod.DYNAMIC
                    
                    merged_candidate = FlagCandidate(
                        candidate=merged_str,
                        score=merged_score,
                        method=method,
                        source=f"merged: {cand1.source} + {cand2.source}"
                    )
                    merged.append(merged_candidate)
        
        return merged
    
    def merge_all(self, candidates: List[FlagCandidate]) -> List[FlagCandidate]:
        """
        Apply all merging strategies.
        
        Args:
            candidates: List of flag candidates
        
        Returns:
            List of original + merged candidates
        """
        all_candidates = list(candidates)
        
        # Apply prefix/suffix merging
        prefix_suffix_merged = self.find_prefix_suffix_matches(candidates)
        all_candidates.extend(prefix_suffix_merged)
        
        # Apply common subsequence merging
        subsequence_merged = self.find_common_subsequence_merges(candidates)
        all_candidates.extend(subsequence_merged)
        
        return all_candidates

