"""
Dynamic analysis module using ltrace and strace.
"""

import os
import subprocess
import re
from typing import List, Optional
from flagscent.models import AnalysisMethod


class DynamicAnalyzer:
    """Dynamic analysis using ltrace and strace."""
    
    def __init__(self, binary_path: str):
        """
        Initialize dynamic analyzer.
        
        Args:
            binary_path: Path to ELF binary
        """
        self.binary_path = binary_path
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
    
    def _check_tool_available(self, tool: str) -> bool:
        """Check if external tool is available."""
        try:
            subprocess.run(
                [tool, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def run_ltrace(self, input_data: Optional[bytes] = None) -> List[dict]:
        """
        Run ltrace and capture function calls.
        
        Args:
            input_data: Optional input to feed to binary
        
        Returns:
            List of captured candidates with source info
        """
        candidates = []
        
        if not self._check_tool_available("ltrace"):
            return candidates
        
        try:
            # Run ltrace with strcmp, memcmp, puts, printf monitoring
            cmd = [
                "ltrace",
                "-e", "strcmp+memcmp+strncmp+puts+printf",
                self.binary_path
            ]
            
            if input_data:
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = process.communicate(input=input_data, timeout=10)
            else:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10
                )
                stdout = result.stdout
                stderr = result.stderr
            
            # Parse ltrace output
            candidates.extend(self._parse_ltrace_output(stderr.decode('utf-8', errors='ignore')))
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            # Analysis failed, return empty list
            pass
        
        return candidates
    
    def _parse_ltrace_output(self, output: str) -> List[dict]:
        """
        Parse ltrace output to extract function call arguments.
        
        Args:
            output: ltrace stderr output
        
        Returns:
            List of candidate dictionaries
        """
        candidates = []
        
        # Pattern for strcmp/strncmp calls: strcmp("arg1", "arg2")
        patterns = [
            (r'strcmp\("([^"]+)"', "strcmp"),
            (r'strncmp\("([^"]+)"', "strncmp"),
            (r'memcmp\("([^"]+)"', "memcmp"),
        ]
        
        for pattern, func_name in patterns:
            matches = re.finditer(pattern, output)
            for match in matches:
                arg = match.group(1)
                candidates.append({
                    "candidate": arg,
                    "method": AnalysisMethod.DYNAMIC,
                    "source": f"ltrace {func_name}"
                })
        
        return candidates
    
    def run_strace(self, input_data: Optional[bytes] = None) -> List[dict]:
        """
        Run strace and monitor syscalls.
        
        Args:
            input_data: Optional input to feed to binary
        
        Returns:
            List of captured candidates
        """
        candidates = []
        
        if not self._check_tool_available("strace"):
            return candidates
        
        try:
            cmd = ["strace", "-e", "read,write", self.binary_path]
            
            if input_data:
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = process.communicate(input=input_data, timeout=10)
            else:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10
                )
                stdout = result.stdout
                stderr = result.stderr
            
            # Parse strace output for interesting data
            # TODO: Implement parsing logic
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
        
        return candidates
    
    def analyze(self, input_data: Optional[bytes] = None) -> List[dict]:
        """
        Perform full dynamic analysis.
        
        Args:
            input_data: Optional input to feed to binary
        
        Returns:
            List of candidate dictionaries
        """
        candidates = []
        
        # Run ltrace
        candidates.extend(self.run_ltrace(input_data))
        
        # Run strace (supplementary)
        candidates.extend(self.run_strace(input_data))
        
        return candidates

