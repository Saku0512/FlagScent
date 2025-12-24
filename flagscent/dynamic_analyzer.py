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
        
        # Check if binary is executable (ltrace requires executable)
        if not os.access(self.binary_path, os.X_OK):
            # Try to make it executable temporarily
            original_mode = os.stat(self.binary_path).st_mode
            try:
                os.chmod(self.binary_path, original_mode | 0o111)
            except OSError:
                # Can't make executable, skip ltrace
                return candidates
        
        try:
            # Run ltrace with strcmp, memcmp, puts, printf monitoring
            # -f: follow forks
            # -e: trace only specified functions
            # -s: string length limit (increase for longer flags)
            cmd = [
                "ltrace",
                "-f",  # Follow child processes
                "-s", "2000",  # String length limit (increased for longer flags)
                "-e", "strcmp+strncmp+memcmp+puts+printf+fputs+fprintf",
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
            ltrace_output = stderr.decode('utf-8', errors='ignore')
            parsed_candidates = self._parse_ltrace_output(ltrace_output)
            candidates.extend(parsed_candidates)
            
        except subprocess.TimeoutExpired:
            # Timeout - binary took too long, return what we have
            pass
        except subprocess.CalledProcessError:
            # ltrace failed (e.g., binary not executable), return empty list
            pass
        except Exception:
            # Other errors, return empty list
            pass
        finally:
            # Restore original permissions if we changed them
            if 'original_mode' in locals():
                try:
                    os.chmod(self.binary_path, original_mode)
                except OSError:
                    pass
        
        return candidates
    
    def _parse_ltrace_output(self, output: str) -> List[dict]:
        """
        Parse ltrace output to extract function call arguments.
        
        ltrace output format examples:
        - strcmp("CTF{flag}", "input") = -1
        - strcmp("arg1"..., "arg2"...) = -1  (with truncation)
        - strncmp("flag{test}", "input", 10) = -1
        - memcmp("data", "input", 4) = 1
        - puts("CTF{found_flag}") = 13
        - printf("flag: %s", "CTF{value}") = 15
        
        Note: ltrace may escape quotes and truncate long strings with "..."
        
        Args:
            output: ltrace stderr output
        
        Returns:
            List of candidate dictionaries
        """
        candidates = []
        seen = set()  # Avoid duplicates
        
        # Helper function to extract string arguments, handling escaped quotes and truncation
        def extract_string_args(pattern_base: str, output: str):
            """Extract string arguments from function calls, handling various formats."""
            # Pattern variants:
            # 1. Normal: strcmp("arg1", "arg2")
            # 2. Escaped: strcmp(\"arg1\", \"arg2\")
            # 3. Truncated: strcmp("arg1"..., "arg2"...)
            # 4. Escaped + Truncated: strcmp(\"arg1\"..., \"arg2\"...)
            
            patterns = [
                # Normal quotes, no truncation
                pattern_base.replace('"', r'"(?:[^"\\]|\\.)*?"'),
                # Escaped quotes, no truncation
                pattern_base.replace('"', r'\\"(?:[^"\\]|\\.)*?\\"'),
                # Normal quotes, with truncation
                pattern_base.replace('"', r'"(?:[^"\\]|\\.)*?"(?:\.\.\.)?'),
                # Escaped quotes, with truncation
                pattern_base.replace('"', r'\\"(?:[^"\\]|\\.)*?\\"(?:\.\.\.)?'),
            ]
            
            results = []
            for pattern in patterns:
                for match in re.finditer(pattern, output):
                    # Extract arguments (skip function name)
                    groups = match.groups()
                    if len(groups) >= 2:
                        results.append((groups[0], groups[1]))
                    elif len(groups) == 1:
                        results.append((groups[0],))
            
            return results
        
        # Pattern for strcmp: strcmp("arg1", "arg2")
        # Handle both normal and escaped quotes, with or without truncation
        strcmp_patterns = [
            r'strcmp\("([^"]+)"(?:\.\.\.)?,\s*"([^"]+)"(?:\.\.\.)?\)',
            r'strcmp\\("([^"]+)\\"(?:\.\.\.)?,\s*\\"([^"]+)\\"(?:\.\.\.)?\\)',
        ]
        for pattern in strcmp_patterns:
            for match in re.finditer(pattern, output):
                arg1, arg2 = match.groups()
                for arg in [arg1, arg2]:
                    if arg and arg not in seen and len(arg) > 0:
                        seen.add(arg)
                        candidates.append({
                            "candidate": arg,
                            "method": AnalysisMethod.DYNAMIC,
                            "source": "ltrace strcmp"
                        })
        
        # Pattern for strncmp: strncmp("arg1", "arg2", n)
        strncmp_patterns = [
            r'strncmp\("([^"]+)"(?:\.\.\.)?,\s*"([^"]+)"(?:\.\.\.)?,\s*\d+\)',
            r'strncmp\\("([^"]+)\\"(?:\.\.\.)?,\s*\\"([^"]+)\\"(?:\.\.\.)?,\s*\d+\\)',
        ]
        for pattern in strncmp_patterns:
            for match in re.finditer(pattern, output):
                arg1, arg2 = match.groups()
                for arg in [arg1, arg2]:
                    if arg and arg not in seen and len(arg) > 0:
                        seen.add(arg)
                        candidates.append({
                            "candidate": arg,
                            "method": AnalysisMethod.DYNAMIC,
                            "source": "ltrace strncmp"
                        })
        
        # Pattern for memcmp: memcmp("arg1", "arg2", n)
        memcmp_patterns = [
            r'memcmp\("([^"]+)"(?:\.\.\.)?,\s*"([^"]+)"(?:\.\.\.)?,\s*\d+\)',
            r'memcmp\\("([^"]+)\\"(?:\.\.\.)?,\s*\\"([^"]+)\\"(?:\.\.\.)?,\s*\d+\\)',
        ]
        for pattern in memcmp_patterns:
            for match in re.finditer(pattern, output):
                arg1, arg2 = match.groups()
                for arg in [arg1, arg2]:
                    if arg and arg not in seen and len(arg) > 0:
                        seen.add(arg)
                        candidates.append({
                            "candidate": arg,
                            "method": AnalysisMethod.DYNAMIC,
                            "source": "ltrace memcmp"
                        })
        
        # Pattern for puts: puts("string")
        puts_patterns = [
            r'puts\("([^"]+)"(?:\.\.\.)?\)',
            r'puts\\("([^"]+)\\"(?:\.\.\.)?\\)',
        ]
        for pattern in puts_patterns:
            for match in re.finditer(pattern, output):
                arg = match.group(1)
                if arg and arg not in seen and len(arg) > 0:
                    seen.add(arg)
                    candidates.append({
                        "candidate": arg,
                        "method": AnalysisMethod.DYNAMIC,
                        "source": "ltrace puts"
                    })
        
        # Pattern for printf: printf("format", ...) or printf("string")
        printf_patterns = [
            r'printf\("([^"]+)"(?:\.\.\.)?\)',
            r'printf\("([^"]+)"(?:\.\.\.)?,\s*"([^"]+)"(?:\.\.\.)?\)',
            r'printf\\("([^"]+)\\"(?:\.\.\.)?\\)',
            r'printf\\("([^"]+)\\"(?:\.\.\.)?,\s*\\"([^"]+)\\"(?:\.\.\.)?\\)',
        ]
        for pattern in printf_patterns:
            for match in re.finditer(pattern, output):
                groups = match.groups()
                for arg in groups:
                    if arg and arg not in seen and len(arg) > 0:
                        seen.add(arg)
                        candidates.append({
                            "candidate": arg,
                            "method": AnalysisMethod.DYNAMIC,
                            "source": "ltrace printf"
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
            # Use -s to show full strings, -e to filter syscalls
            cmd = [
                "strace",
                "-s", "1000",  # Show up to 1000 chars per string
                "-e", "read,write",
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
            
            # Parse strace output
            candidates.extend(self._parse_strace_output(stderr.decode('utf-8', errors='ignore')))
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
        
        return candidates
    
    def _parse_strace_output(self, output: str) -> List[dict]:
        """
        Parse strace output to extract string data from syscalls.
        
        strace output format examples:
        - read(0, "CTF{flag_input}", 100) = 15
        - write(1, "CTF{found_flag}", 15) = 15
        
        Args:
            output: strace stderr output
        
        Returns:
            List of candidate dictionaries
        """
        candidates = []
        seen = set()  # Avoid duplicates
        
        # Pattern for read syscall: read(fd, "data", size)
        # Usually we're interested in data being read
        read_pattern = r'read\(\d+,\s*"([^"]+)"'
        for match in re.finditer(read_pattern, output):
            data = match.group(1)
            if data and data not in seen:
                seen.add(data)
                candidates.append({
                    "candidate": data,
                    "method": AnalysisMethod.DYNAMIC,
                    "source": "strace read"
                })
        
        # Pattern for write syscall: write(fd, "data", size)
        # Output data might contain flags
        write_pattern = r'write\(\d+,\s*"([^"]+)"'
        for match in re.finditer(write_pattern, output):
            data = match.group(1)
            if data and data not in seen:
                seen.add(data)
                candidates.append({
                    "candidate": data,
                    "method": AnalysisMethod.DYNAMIC,
                    "source": "strace write"
                })
        
        # Also look for hex-encoded data: read(0, "\x43\x54\x46\x7b...", ...)
        # Convert hex sequences to strings
        hex_read_pattern = r'read\(\d+,\s*"((?:\\x[0-9a-fA-F]{2})+)"'
        for match in re.finditer(hex_read_pattern, output):
            hex_data = match.group(1)
            try:
                # Decode hex escape sequences
                decoded = bytes(hex_data, 'utf-8').decode('unicode_escape')
                # Check if it's printable
                if decoded.isprintable() and decoded not in seen:
                    seen.add(decoded)
                    candidates.append({
                        "candidate": decoded,
                        "method": AnalysisMethod.DYNAMIC,
                        "source": "strace read (hex)"
                    })
            except (UnicodeDecodeError, ValueError):
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

