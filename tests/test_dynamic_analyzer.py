"""
Tests for dynamic analyzer.
"""

import pytest
import tempfile
import os
from flagscent.dynamic_analyzer import DynamicAnalyzer
from flagscent.models import AnalysisMethod


class TestDynamicAnalyzer:
    """Tests for DynamicAnalyzer class."""
    
    def test_init_with_existing_file(self):
        """Test initializing with existing file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy binary content")
            temp_path = f.name
        
        try:
            analyzer = DynamicAnalyzer(temp_path)
            assert analyzer.binary_path == os.path.abspath(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_init_with_nonexistent_file(self):
        """Test initializing with non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            DynamicAnalyzer("/nonexistent/path/to/binary")
    
    def test_check_tool_available(self):
        """Test tool availability check."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = DynamicAnalyzer(temp_path)
            # Should not raise exception
            result = analyzer._check_tool_available("echo")
            # echo should be available on most systems
            assert isinstance(result, bool)
        finally:
            os.unlink(temp_path)
    
    def test_parse_ltrace_output(self):
        """Test parsing ltrace output."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = DynamicAnalyzer(temp_path)
            
            # Sample ltrace output
            ltrace_output = """
strcmp("CTF{test_flag}", "input")
strncmp("flag{another}", "input", 10)
memcmp("data", "input", 4)
"""
            
            candidates = analyzer._parse_ltrace_output(ltrace_output)
            
            # Should extract candidates
            assert isinstance(candidates, list)
            # Should have found some candidates
            assert len(candidates) > 0
            
            # Check structure
            for candidate in candidates:
                assert isinstance(candidate, dict)
                assert "candidate" in candidate
                assert "method" in candidate
                assert "source" in candidate
                assert candidate["method"] == AnalysisMethod.DYNAMIC
        
        finally:
            os.unlink(temp_path)
    
    def test_parse_ltrace_output_empty(self):
        """Test parsing empty ltrace output."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = DynamicAnalyzer(temp_path)
            candidates = analyzer._parse_ltrace_output("")
            assert candidates == []
        finally:
            os.unlink(temp_path)
    
    def test_run_ltrace_handles_missing_tool(self):
        """Test that run_ltrace handles missing tool gracefully."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = DynamicAnalyzer(temp_path)
            # Mock check to return False
            analyzer._check_tool_available = lambda x: False
            
            candidates = analyzer.run_ltrace()
            # Should return empty list, not raise exception
            assert candidates == []
        finally:
            os.unlink(temp_path)
    
    def test_analyze_returns_list(self):
        """Test analyze returns list of candidates."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = DynamicAnalyzer(temp_path)
            # Mock tool checks to avoid requiring actual tools
            analyzer._check_tool_available = lambda x: False
            
            results = analyzer.analyze()
            # Should return a list
            assert isinstance(results, list)
        finally:
            os.unlink(temp_path)

