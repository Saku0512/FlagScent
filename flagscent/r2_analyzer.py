"""
Radare2 analysis utilities for binary structure analysis.
Provides interactive-like r2 commands through r2pipe.
"""

import os
from typing import List, Dict, Optional
from flagscent.static_analyzer import StaticAnalyzer


class R2Analyzer:
    """
    Extended radare2 analyzer for detailed binary structure analysis.
    Provides methods similar to interactive r2 commands.
    """
    
    def __init__(self, binary_path: str):
        """
        Initialize R2 analyzer.
        
        Args:
            binary_path: Path to ELF binary
        """
        self.binary_path = binary_path
        self.static_analyzer = StaticAnalyzer(binary_path)
    
    def afl(self) -> List[Dict]:
        """
        Analyze function list (equivalent to 'afl' command).
        
        Returns:
            List of function dictionaries
        """
        return self.static_analyzer.get_function_list()
    
    def pdf(self, function_name: str = "main") -> str:
        """
        Print disassembly of function (equivalent to 'pdf @ function').
        
        Args:
            function_name: Name of function to disassemble (default: "main")
        
        Returns:
            Disassembly output
        """
        return self.static_analyzer.disassemble_function(function_name)
    
    def analyze_structure(self) -> Dict:
        """
        Analyze binary structure comprehensively.
        
        Returns:
            Dictionary with complete analysis
        """
        return self.static_analyzer.analyze_binary_structure()
    
    def find_string_xrefs(self, target_string: str) -> List[Dict]:
        """
        Find cross-references to a string (equivalent to finding string and using 'axt').
        
        Args:
            target_string: String to search for
        
        Returns:
            List of reference locations
        """
        return self.static_analyzer.find_string_references(target_string)
    
    def get_imports(self) -> List[str]:
        """
        Get imported functions (equivalent to 'ii').
        
        Returns:
            List of imported function names
        """
        return self.static_analyzer.identify_imported_functions()
    
    def print_summary(self) -> str:
        """
        Print a summary of binary analysis (similar to r2 info commands).
        
        Returns:
            Formatted summary string
        """
        structure = self.analyze_structure()
        imports = self.get_imports()
        
        summary = []
        summary.append("=" * 60)
        summary.append("Binary Analysis Summary")
        summary.append("=" * 60)
        
        # Entry point
        if structure.get('entry_point'):
            summary.append(f"\nEntry Point: 0x{structure['entry_point']:x}")
        
        # Functions
        functions = structure.get('functions', [])
        summary.append(f"\nFunctions: {len(functions)}")
        if functions:
            summary.append("\nKey Functions:")
            for func in functions[:10]:  # Show first 10
                name = func.get('name', 'unknown')
                addr = func.get('address', 0)
                size = func.get('size', 0)
                summary.append(f"  {name:30s} @ 0x{addr:x} (size: {size})")
            if len(functions) > 10:
                summary.append(f"  ... and {len(functions) - 10} more")
        
        # Main function
        if structure.get('main_function'):
            main = structure['main_function']
            summary.append(f"\nMain Function:")
            summary.append(f"  Name: {main.get('name', 'unknown')}")
            summary.append(f"  Address: 0x{main.get('address', 0):x}")
            summary.append(f"  Size: {main.get('size', 0)} bytes")
        
        # Imports
        summary.append(f"\nImported Functions: {len(imports)}")
        if imports:
            # Filter for interesting functions
            interesting = [f for f in imports if any(
                fn in f.lower() for fn in ['strcmp', 'memcmp', 'puts', 'printf', 'read', 'write']
            )]
            if interesting:
                summary.append("\nInteresting Imports:")
                for imp in interesting[:10]:
                    summary.append(f"  - {imp}")
        
        summary.append("\n" + "=" * 60)
        
        return "\n".join(summary)

