"""
Tests for static analyzer.
"""

import pytest
import tempfile
import os
from pathlib import Path
from flagscent.static_analyzer import StaticAnalyzer


class TestStaticAnalyzer:
    """Tests for StaticAnalyzer class."""
    
    def test_init_with_existing_file(self):
        """Test initializing with existing file."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy binary content")
            temp_path = f.name
        
        try:
            analyzer = StaticAnalyzer(temp_path)
            assert analyzer.binary_path == os.path.abspath(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_init_with_nonexistent_file(self):
        """Test initializing with non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            StaticAnalyzer("/nonexistent/path/to/binary")
    
    def test_extract_strings_placeholder(self):
        """Test extract_strings returns list (placeholder)."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = StaticAnalyzer(temp_path)
            strings = analyzer.extract_strings()
            # Should return a list (even if empty for now)
            assert isinstance(strings, list)
        finally:
            os.unlink(temp_path)
    
    def test_identify_imported_functions_placeholder(self):
        """Test identify_imported_functions returns list (placeholder)."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = StaticAnalyzer(temp_path)
            functions = analyzer.identify_imported_functions()
            # Should return a list (even if empty for now)
            assert isinstance(functions, list)
        finally:
            os.unlink(temp_path)
    
    def test_find_string_references_placeholder(self):
        """Test find_string_references returns list (placeholder)."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = StaticAnalyzer(temp_path)
            refs = analyzer.find_string_references("test")
            # Should return a list (even if empty for now)
            assert isinstance(refs, list)
        finally:
            os.unlink(temp_path)
    
    def test_analyze_returns_list(self):
        """Test analyze returns list of candidates."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"dummy")
            temp_path = f.name
        
        try:
            analyzer = StaticAnalyzer(temp_path)
            results = analyzer.analyze()
            # Should return a list
            assert isinstance(results, list)
            # Each result should be a dict with expected keys
            for result in results:
                assert isinstance(result, dict)
                assert "candidate" in result
                assert "method" in result
                assert "source" in result
        finally:
            os.unlink(temp_path)

