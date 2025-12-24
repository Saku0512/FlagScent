"""
Main analyzer orchestrating static, dynamic, and symbolic analysis.
"""

import os
from typing import List
from flagscent.models import FlagCandidate, AnalysisMethod
from flagscent.static_analyzer import StaticAnalyzer
from flagscent.dynamic_analyzer import DynamicAnalyzer
from flagscent.symbolic_analyzer import SymbolicAnalyzer
from flagscent.scorer import score_candidate, rank_candidates


class FlagScentAnalyzer:
    """Main analyzer for FlagScent."""
    
    def __init__(self, binary_path: str):
        """
        Initialize analyzer.
        
        Args:
            binary_path: Path to ELF binary
        """
        self.binary_path = os.path.abspath(binary_path)
        self.static_analyzer = StaticAnalyzer(self.binary_path)
        self.dynamic_analyzer = DynamicAnalyzer(self.binary_path)
        self.symbolic_analyzer = SymbolicAnalyzer(self.binary_path)
    
    def analyze(self, enable_symbolic: bool = True, symbolic_timeout: int = 30) -> List[FlagCandidate]:
        """
        Perform complete analysis.
        
        Args:
            enable_symbolic: Whether to enable symbolic execution
            symbolic_timeout: Timeout for symbolic execution
        
        Returns:
            Ranked list of flag candidates
        """
        all_candidates = []
        
        # Static analysis
        print("[*] Running static analysis...")
        static_results = self.static_analyzer.analyze()
        for result in static_results:
            candidate = score_candidate(
                result["candidate"],
                result["method"],
                result["source"]
            )
            all_candidates.append(candidate)
        
        # Dynamic analysis
        print("[*] Running dynamic analysis...")
        dynamic_results = self.dynamic_analyzer.analyze()
        for result in dynamic_results:
            candidate = score_candidate(
                result["candidate"],
                result["method"],
                result["source"]
            )
            all_candidates.append(candidate)
        
        # Symbolic execution (optional)
        if enable_symbolic:
            print("[*] Running symbolic execution (time-limited)...")
            symbolic_results = self.symbolic_analyzer.analyze(timeout=symbolic_timeout)
            for result in symbolic_results:
                candidate = score_candidate(
                    result["candidate"],
                    result["method"],
                    result["source"]
                )
                all_candidates.append(candidate)
        
        # Remove duplicates (same candidate string)
        seen = set()
        unique_candidates = []
        for candidate in all_candidates:
            if candidate.candidate not in seen:
                seen.add(candidate.candidate)
                unique_candidates.append(candidate)
        
        # Rank candidates
        ranked = rank_candidates(unique_candidates)
        
        return ranked

