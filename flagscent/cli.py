"""
Command-line interface for FlagScent.
"""

import argparse
import json
import sys
from pathlib import Path
from flagscent import __version__
from flagscent.analyzer import FlagScentAnalyzer
from flagscent.r2_analyzer import R2Analyzer


def print_candidates(candidates, limit: int = 10):
    """
    Print ranked candidates in human-readable format with explainability.
    
    Args:
        candidates: List of FlagCandidate objects
        limit: Maximum number of candidates to display
    """
    print("\n" + "=" * 60)
    print("Flag Candidates (ranked by score)")
    print("=" * 60)
    
    for i, candidate in enumerate(candidates[:limit], 1):
        print(f"\n[{i}] score={candidate.score:.1f}  {candidate.candidate}")
        print(f"    Method: {candidate.method.value}")
        print(f"    Evidence:")
        
        # Parse source for better display
        if "merged:" in candidate.source:
            # Show merge evidence
            parts = candidate.source.replace("merged: ", "").split(" + ")
            for part in parts:
                print(f"      - {part.strip()}")
        else:
            print(f"      - {candidate.source}")
    
    if len(candidates) > limit:
        print(f"\n... and {len(candidates) - limit} more candidates")
    
    print("\n" + "=" * 60)


def output_json(candidates, output_file: str = None):
    """
    Output candidates in JSON format.
    
    Args:
        candidates: List of FlagCandidate objects
        output_file: Optional output file path (stdout if None)
    """
    json_data = [c.to_dict() for c in candidates]
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"[*] JSON output written to {output_file}")
    else:
        print(json.dumps(json_data, indent=2))


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="FlagScent - Automated flag candidate discovery for CTF reverse engineering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Flag candidate discovery
  flagscent binary                    # Analyze binary and show top candidates
  flagscent binary --json output.json # Output results as JSON
  flagscent binary --no-symbolic      # Skip symbolic execution
  flagscent binary --limit 20         # Show top 20 candidates
  
  # Binary structure analysis
  flagscent binary --analyze          # Show binary structure (functions, imports, etc.)
  flagscent binary --disassemble main # Disassemble specific function
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"FlagScent {__version__}"
    )
    
    parser.add_argument(
        "binary",
        type=str,
        nargs="?",
        help="Path to ELF binary to analyze"
    )
    
    parser.add_argument(
        "--json",
        type=str,
        metavar="FILE",
        help="Output results as JSON to file (or stdout if '-' specified)"
    )
    
    parser.add_argument(
        "--no-symbolic",
        action="store_true",
        help="Disable symbolic execution analysis"
    )
    
    parser.add_argument(
        "--symbolic-timeout",
        type=int,
        default=30,
        help="Timeout for symbolic execution in seconds (default: 30)"
    )
    
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of candidates to display (default: 10)"
    )
    
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Show binary structure analysis (functions, imports, etc.)"
    )
    
    parser.add_argument(
        "--disassemble",
        type=str,
        metavar="FUNCTION",
        help="Disassemble a specific function (e.g., 'main')"
    )
    
    args = parser.parse_args()
    
    # Check if binary is provided
    if not args.binary:
        parser.error("the following arguments are required: binary")
    
    # Validate binary path
    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"Error: Binary not found: {args.binary}", file=sys.stderr)
        sys.exit(1)
    
    # Handle structure analysis or disassembly requests
    if args.analyze or args.disassemble:
        try:
            r2_analyzer = R2Analyzer(str(binary_path))
            
            if args.disassemble:
                # Disassemble specific function
                disasm = r2_analyzer.pdf(args.disassemble)
                if disasm:
                    print(f"\nDisassembly of function '{args.disassemble}':")
                    print("=" * 60)
                    print(disasm)
                else:
                    print(f"Error: Function '{args.disassemble}' not found or r2pipe not available", file=sys.stderr)
                    sys.exit(1)
            
            if args.analyze:
                # Show structure analysis
                summary = r2_analyzer.print_summary()
                print(summary)
                
                # Also show main function disassembly if available
                structure = r2_analyzer.analyze_structure()
                if structure.get('main_function'):
                    main_name = structure['main_function'].get('name', 'main')
                    print(f"\n\nDisassembly of '{main_name}':")
                    print("=" * 60)
                    disasm = r2_analyzer.pdf(main_name)
                    if disasm:
                        print(disasm)
            
            sys.exit(0)
            
        except Exception as e:
            print(f"Error during analysis: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Create analyzer and run analysis
    try:
        analyzer = FlagScentAnalyzer(str(binary_path))
        candidates = analyzer.analyze(
            enable_symbolic=not args.no_symbolic,
            symbolic_timeout=args.symbolic_timeout
        )
        
        # Output results
        if args.json:
            if args.json == "-":
                output_json(candidates, None)
            else:
                output_json(candidates, args.json)
        else:
            print_candidates(candidates, limit=args.limit)
        
        if not candidates:
            print("\n[*] No flag candidates found.")
            sys.exit(1)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

