"""
Pytest configuration and shared fixtures.
"""

import pytest
import tempfile
import os


@pytest.fixture
def temp_binary():
    """Create a temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"dummy binary content for testing")
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def sample_flag_candidates():
    """Sample flag candidates for testing."""
    from flagscent.models import FlagCandidate, AnalysisMethod
    
    return [
        FlagCandidate("CTF{perfect_flag}", 95.0, AnalysisMethod.DYNAMIC, "ltrace"),
        FlagCandidate("flag{good_flag}", 85.0, AnalysisMethod.SYMBOLIC, "angr"),
        FlagCandidate("not_a_flag", 20.0, AnalysisMethod.STATIC, "strings"),
        FlagCandidate("CTF{another}", 80.0, AnalysisMethod.STATIC, "strings"),
    ]

