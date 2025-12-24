"""
Tests for main analyzer.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch
from flagscent.analyzer import FlagScentAnalyzer
from flagscent.models import AnalysisMethod, FlagCandidate


class TestFlagScentAnalyzer:
    """Tests for FlagScentAnalyzer class."""
    
    def test_init(self):
        """Test analyzer initialization."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy binary")
            temp_path = f.name
        
        try:
            analyzer = FlagScentAnalyzer(temp_path)
            assert analyzer.binary_path == os.path.abspath(temp_path)
            assert analyzer.static_analyzer is not None
            assert analyzer.dynamic_analyzer is not None
            assert analyzer.symbolic_analyzer is not None
        finally:
            os.unlink(temp_path)
    
    @patch('flagscent.analyzer.StaticAnalyzer')
    @patch('flagscent.analyzer.DynamicAnalyzer')
    @patch('flagscent.analyzer.SymbolicAnalyzer')
    @patch('flagscent.analyzer.score_candidate')
    @patch('flagscent.analyzer.rank_candidates')
    def test_analyze_integration(self, mock_rank, mock_score, 
                                  mock_sym, mock_dyn, mock_static):
        """Test full analysis integration."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            # Setup mocks
            mock_static_instance = Mock()
            mock_static_instance.analyze.return_value = [
                {"candidate": "CTF{static}", "method": AnalysisMethod.STATIC, 
                 "source": "static"}
            ]
            mock_static.return_value = mock_static_instance
            
            mock_dyn_instance = Mock()
            mock_dyn_instance.analyze.return_value = [
                {"candidate": "CTF{dynamic}", "method": AnalysisMethod.DYNAMIC,
                 "source": "dynamic"}
            ]
            mock_dyn.return_value = mock_dyn_instance
            
            mock_sym_instance = Mock()
            mock_sym_instance.analyze.return_value = []
            mock_sym.return_value = mock_sym_instance
            
            # Mock score_candidate to return FlagCandidate
            def mock_score_func(candidate, method, source):
                return FlagCandidate(
                    candidate=candidate,
                    score=85.0,
                    method=method,
                    source=source
                )
            mock_score.side_effect = mock_score_func
            
            # Mock rank_candidates to return as-is
            mock_rank.side_effect = lambda x: x
            
            # Create analyzer and run
            analyzer = FlagScentAnalyzer(temp_path)
            results = analyzer.analyze(enable_symbolic=False)
            
            # Verify results
            assert isinstance(results, list)
            assert len(results) >= 2  # At least static and dynamic
            
            # Verify mocks were called
            mock_static_instance.analyze.assert_called_once()
            mock_dyn_instance.analyze.assert_called_once()
            
        finally:
            os.unlink(temp_path)
    
    @patch('flagscent.analyzer.StaticAnalyzer')
    @patch('flagscent.analyzer.DynamicAnalyzer')
    @patch('flagscent.analyzer.SymbolicAnalyzer')
    @patch('flagscent.analyzer.score_candidate')
    @patch('flagscent.analyzer.rank_candidates')
    def test_analyze_removes_duplicates(self, mock_rank, mock_score,
                                         mock_sym, mock_dyn, mock_static):
        """Test that duplicate candidates are removed."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            # Setup mocks with duplicate candidate
            duplicate_candidate = "CTF{duplicate}"
            
            mock_static_instance = Mock()
            mock_static_instance.analyze.return_value = [
                {"candidate": duplicate_candidate, "method": AnalysisMethod.STATIC,
                 "source": "static"}
            ]
            mock_static.return_value = mock_static_instance
            
            mock_dyn_instance = Mock()
            mock_dyn_instance.analyze.return_value = [
                {"candidate": duplicate_candidate, "method": AnalysisMethod.DYNAMIC,
                 "source": "dynamic"}
            ]
            mock_dyn.return_value = mock_dyn_instance
            
            mock_sym_instance = Mock()
            mock_sym_instance.analyze.return_value = []
            mock_sym.return_value = mock_sym_instance
            
            def mock_score_func(candidate, method, source):
                return FlagCandidate(candidate, 85.0, method, source)
            mock_score.side_effect = mock_score_func
            mock_rank.side_effect = lambda x: x
            
            analyzer = FlagScentAnalyzer(temp_path)
            results = analyzer.analyze(enable_symbolic=False)
            
            # Should have only one unique candidate
            unique_candidates = set(c.candidate for c in results)
            assert len(unique_candidates) == 1
            assert duplicate_candidate in unique_candidates
            
        finally:
            os.unlink(temp_path)
    
    @patch('flagscent.analyzer.StaticAnalyzer')
    @patch('flagscent.analyzer.DynamicAnalyzer')
    @patch('flagscent.analyzer.SymbolicAnalyzer')
    def test_analyze_with_symbolic_disabled(self, mock_sym, mock_dyn, mock_static):
        """Test analysis with symbolic execution disabled."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            mock_static_instance = Mock()
            mock_static_instance.analyze.return_value = []
            mock_static.return_value = mock_static_instance
            
            mock_dyn_instance = Mock()
            mock_dyn_instance.analyze.return_value = []
            mock_dyn.return_value = mock_dyn_instance
            
            mock_sym_instance = Mock()
            mock_sym.return_value = mock_sym_instance
            
            analyzer = FlagScentAnalyzer(temp_path)
            analyzer.analyze(enable_symbolic=False)
            
            # Symbolic analyzer should not be called
            mock_sym_instance.analyze.assert_not_called()
            
        finally:
            os.unlink(temp_path)

