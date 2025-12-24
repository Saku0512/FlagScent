"""
Static analysis module using radare2.
"""

import os
import subprocess
from typing import List, Optional
from flagscent.models import AnalysisMethod


class StaticAnalyzer:
    """Static analysis using radare2."""
    
    def __init__(self, binary_path: str):
        """
        Initialize static analyzer.
        
        Args:
            binary_path: Path to ELF binary
        """
        self.binary_path = binary_path
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
    
    def _check_r2pipe_available(self) -> bool:
        """Check if r2pipe is available."""
        try:
            import r2pipe
            return True
        except ImportError:
            return False
    
    def _is_noise_string(self, s: str) -> bool:
        """
        Check if a string is likely noise (function names, library paths, etc.).
        
        Args:
            s: String to check
        
        Returns:
            True if string is likely noise
        """
        # Common noise patterns
        noise_patterns = [
            '/lib', '/usr', '/opt',  # Library paths
            '.so', '.dylib', '.dll',  # Library extensions
            '__', '_ITM_', '_GLOBAL_',  # Compiler symbols
            'GCC:', 'clang',  # Compiler info
            'GLIBC', 'libc',  # Library names
            'stack_chk', 'register_tm', 'deregister_tm',  # Security/init functions
            'frame_dummy', 'do_global',  # Init functions
        ]
        
        s_lower = s.lower()
        for pattern in noise_patterns:
            if pattern.lower() in s_lower:
                return True
        
        # Very short strings are likely noise
        if len(s) < 4:
            return True
        
        # Function-like names (all caps with underscores, or camelCase)
        if s.replace('_', '').replace('-', '').isalnum() and '_' in s:
            if s.isupper() or (s[0].isupper() and any(c.islower() for c in s)):
                # Could be a function name, but check if it looks like a flag
                if not any(prefix in s for prefix in ['CTF{', 'flag{', 'FLAG{', 'ctf{']):
                    return True
        
        return False
    
    def extract_strings(self) -> List[str]:
        """
        Extract printable strings from binary using radare2.
        
        Returns:
            List of extracted strings
        """
        strings = []
        
        if not self._check_r2pipe_available():
            # Fallback to strings command if r2pipe not available
            return self._extract_strings_fallback()
        
        try:
            import r2pipe
            
            # Open binary in read-only mode
            r2 = r2pipe.open(self.binary_path, flags=['-2'])  # -2: disable analysis
            
            # Extract strings using radare2
            # Use 'iz' command to extract strings from data sections
            # 'iz' shows strings in format: vaddr=0x... len=N string=...
            result = r2.cmd('iz')
            
            if result:
                for line in result.split('\n'):
                    if 'string=' in line:
                        try:
                            # Extract string value
                            # Format: vaddr=0x... len=N string=value
                            string_part = line.split('string=')[1].strip()
                            # Remove any trailing metadata
                            string_value = string_part.split()[0] if string_part else ""
                            
                            if string_value:
                                # Filter out noise
                                if not self._is_noise_string(string_value):
                                    strings.append(string_value)
                        except (IndexError, ValueError):
                            continue
            
            # Also try 'izz' to get all strings (including in code sections)
            # This might catch more strings but also more noise
            result_all = r2.cmd('izz')
            if result_all:
                for line in result_all.split('\n'):
                    if 'string=' in line:
                        try:
                            string_part = line.split('string=')[1].strip()
                            string_value = string_part.split()[0] if string_part else ""
                            
                            if string_value and string_value not in strings:
                                # Filter out noise
                                if not self._is_noise_string(string_value):
                                    strings.append(string_value)
                        except (IndexError, ValueError):
                            continue
            
            r2.quit()
            
        except Exception:
            # If r2pipe fails, fallback to strings command
            return self._extract_strings_fallback()
        
        return strings
    
    def _extract_strings_fallback(self) -> List[str]:
        """
        Fallback method using 'strings' command.
        
        Returns:
            List of extracted strings
        """
        strings = []
        
        try:
            # Use strings command as fallback
            result = subprocess.run(
                ['strings', self.binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=True
            )
            
            # Filter for reasonable length strings and noise
            seen = set()
            for line in result.stdout.decode('utf-8', errors='ignore').split('\n'):
                s = line.strip()
                if len(s) >= 4 and s not in seen:
                    seen.add(s)
                    # Filter out noise
                    if not self._is_noise_string(s):
                        strings.append(s)
                    
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            # strings command not available or failed
            pass
        
        return strings
    
    def identify_imported_functions(self) -> List[str]:
        """
        Identify imported libc functions (strcmp, memcmp, puts, etc.).
        
        Returns:
            List of function names
        """
        functions = []
        
        if not self._check_r2pipe_available():
            return functions
        
        try:
            import r2pipe
            
            r2 = r2pipe.open(self.binary_path, flags=['-2'])
            
            # Get imported functions using 'ii' command
            result = r2.cmd('ii')
            
            if result:
                # Parse JSON output if available, or text format
                try:
                    import json
                    imports = json.loads(result)
                    if isinstance(imports, list):
                        for imp in imports:
                            if 'name' in imp:
                                functions.append(imp['name'])
                except (json.JSONDecodeError, TypeError):
                    # Fallback to text parsing
                    for line in result.split('\n'):
                        # Look for function names
                        if 'strcmp' in line or 'memcmp' in line or 'puts' in line or 'printf' in line:
                            # Try to extract function name
                            parts = line.split()
                            for part in parts:
                                if any(fn in part for fn in ['strcmp', 'memcmp', 'puts', 'printf', 'strncmp']):
                                    if part not in functions:
                                        functions.append(part)
            
            r2.quit()
            
        except Exception:
            pass
        
        return functions
    
    def find_string_references(self, target_string: str) -> List[dict]:
        """
        Find cross-references to a specific string.
        
        Args:
            target_string: String to search for
        
        Returns:
            List of reference locations (dict with address, function, etc.)
        """
        # TODO: Implement using r2pipe
        return []
    
    def analyze(self) -> List[dict]:
        """
        Perform full static analysis.
        
        Returns:
            List of candidate dictionaries with source information
        """
        candidates = []
        
        # Extract strings
        strings = self.extract_strings()
        seen = set()  # Avoid duplicates
        
        # Priority strings (likely flags) - add source info
        priority_strings = []
        normal_strings = []
        
        for s in strings:
            if s not in seen and len(s) >= 4:
                seen.add(s)
                
                # Check if string looks like a flag
                is_flag_like = any(
                    prefix in s for prefix in 
                    ['CTF{', 'flag{', 'FLAG{', 'ctf{', 'Flag{', 'Alpaca{', 'alpaca{']
                ) or ('{' in s and '}' in s and len(s) >= 15)
                
                if is_flag_like:
                    priority_strings.append(s)
                else:
                    normal_strings.append(s)
        
        # Add priority strings first (they'll be scored higher)
        for s in priority_strings:
            candidates.append({
                "candidate": s,
                "method": AnalysisMethod.STATIC,
                "source": "static string extraction (r2)"
            })
        
        # Add normal strings (but limit to reasonable number to avoid noise)
        # Only add strings that are reasonably long and printable
        for s in normal_strings[:100]:  # Limit to top 100 to reduce noise
            if s.isprintable() and len(s) >= 8:  # Longer strings are more likely to be meaningful
                candidates.append({
                    "candidate": s,
                    "method": AnalysisMethod.STATIC,
                    "source": "static string extraction (r2)"
                })
        
        return candidates

