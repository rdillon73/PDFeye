#!/usr/bin/env python3
"""
PDFEYE - a PDF Malware Analyzer 
(c) Roberto Dillon 2026
==============================================

A comprehensive tool for analyzing PDF files for potential malware and suspicious content.
It can use built-in rules and import user-defined YARA rules.

Features:
- Direct string pattern matching 
- Shannon entropy analysis 
- YARA rule scanning (optional)
- Batch processing for directories
- JSON output format support

Dependencies:
    pip install python-magic yara-python requests   # plus anything else that isn't there ;)

Usage Examples:

# Basic scan
python pdfeye.py document.pdf

# Test with a single PDF with YARA
python pdfeye.py suspicious.pdf --yara pdf_malware_rules.yar

# Batch scan with YARA
python pdfeye.py ./pdfs --batch --yara pdf_malware_rules.yar --json

# Batch scan with JSON output
python pdfeye.py ./pdfs --batch --json --output results.json

# Recursive scan with quiet mode
python pdfeye.py ./documents --batch --recursive --quiet --output scan_results.json

Version: 2.0
"""

import argparse
import json
import math
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

# Optional imports with graceful fallbacks
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available. File type detection disabled.")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# global variable to quantify the overall risk for the file under analysis
riskscore = 0

class PDFAnalysisResult:
    """Container class for PDF analysis results with utility methods."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.is_pdf = False
        self.file_size = 0
        self.entropy = 0.0
        self.suspicious_strings = []
        self.yara_matches = []
        self.analysis_timestamp = time.time()
        self.errors = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis results to dictionary format."""
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "is_pdf": self.is_pdf,
            "entropy": self.entropy,
            "suspicious_strings": self.suspicious_strings,
            "yara_matches": self.yara_matches,
            "analysis_timestamp": self.analysis_timestamp,
            "errors": self.errors
        }
    
    def has_suspicious_content(self) -> bool:
        #Check if the PDF contains any suspicious indicators.
        # changed in v.2.0: now file is labeled as suspicious only if its riskscore is higher than 5
        global riskscore
        return bool(
            #self.suspicious_strings or 
            #self.yara_matches or 
            #self.entropy > 7.7

            riskscore >= 5
        )


class SuspiciousStringDetector:
    """Handles detection of suspicious strings/patterns in PDF files."""
    
    # Comprehensive list of suspicious PDF elements
    SUSPICIOUS_PATTERNS = {
        # JavaScript execution
        r'/JS\b': 'JavaScript Code',
        r'/JavaScript\b': 'JavaScript Code', 
        r'app\.': 'Acrobat JavaScript API',
        
        # Auto-execution triggers
        r'/AA\b': 'Automatic Action',
        r'/OpenAction\b': 'Document Open Action',
        r'/Names\b': 'Named Destinations',
        
        # External connections
        r'/URI\b': 'External URL Reference',
        r'/Launch\b': 'External Application Launch',
        r'/SubmitForm\b': 'Form Submission',
        r'/ImportData\b': 'Data Import Action',
        
        # Obfuscation techniques
        r'/ObjStm\b': 'Object Stream (Potential Obfuscation)',
        r'/Filter\s*/FlateDecode': 'Compressed Content',
        r'/Filter\s*/ASCIIHexDecode': 'Hex Encoded Content',
        r'/Filter\s*/ASCII85Decode': 'Base85 Encoded Content',
        
        # Embedded content
        r'/EmbeddedFile\b': 'Embedded File',
        r'/Filespec\b': 'File Specification',
        r'/F\s*/': 'External File Reference',
        
        # Forms and XFA
        r'/AcroForm\b': 'Interactive Form',
        r'/XFA\b': 'XML Forms Architecture',
        
        # Suspicious functions
        r'eval\s*\(': 'Dynamic Code Evaluation',
        r'unescape\s*\(': 'URL Decoding Function',
        r'String\.fromCharCode': 'Character Code Conversion',
        
        # Shell/system commands (rare but dangerous)
        r'cmd\.exe': 'Windows Command Prompt',
        r'/bin/sh': 'Unix Shell',
        r'powershell': 'PowerShell Command'
    }
    
    def __init__(self):
        """Initialize the string detector with compiled regex patterns."""
        self.compiled_patterns = {
            re.compile(pattern, re.IGNORECASE): description 
            for pattern, description in self.SUSPICIOUS_PATTERNS.items()
        }
    
    def scan_file(self, file_path: str) -> List[Dict[str, str]]:
        """
        Scan a PDF file for suspicious string patterns.
        
        Args:
            file_path: Path to the PDF file to scan
            
        Returns:
            List of dictionaries containing pattern matches and descriptions
        """
        matches = []
        
        try:
            with open(file_path, 'rb') as file:
                # Read file content and decode with error handling
                content = file.read()
                # Use latin-1 encoding to preserve all byte values
                text_content = content.decode('latin-1', errors='ignore')
                
                # Check each compiled pattern
                for pattern, description in self.compiled_patterns.items():
                    if pattern.search(text_content):
                        matches.append({
                            "pattern": pattern.pattern,
                            "description": description,
                            "category": self._categorize_threat(description)
                        })
                        
        except IOError as e:
            raise Exception(f"Failed to read file {file_path}: {e}")
        except Exception as e:
            raise Exception(f"Error scanning file for strings: {e}")
            
        return matches
    
    def _categorize_threat(self, description: str) -> str:
        
        # update the global variable
        global riskscore

        # Categorize the threat level based on description.
        high_risk_keywords = ['JavaScript', 'Launch', 'eval', 'Shell', 'Command']
        medium_risk_keywords = ['Action', 'File', 'Embedded', 'Form']
        # other threats are considered as LOW
        # LOW threats add 1 to riskscore, MEDIUM and HIGH add 1 and 3 more respectively  
        riskscore = riskscore + 1

        desc_upper = description.upper()
        
        for keyword in high_risk_keywords:
            if keyword.upper() in desc_upper:
                riskscore = riskscore + 3
                return "HIGH"
                
        for keyword in medium_risk_keywords:
            if keyword.upper() in desc_upper:
                riskscore = riskscore + 1
                return "MEDIUM"
                
        return "LOW"


class YaraScanner:
    """Handles YARA rule compilation and scanning."""
    
    def __init__(self, rules_file: str):
        """
        Initialize YARA scanner with rules file.
        
        Args:
            rules_file: Path to YARA rules file
            
        Raises:
            Exception: If YARA is not available or rules cannot be compiled
        """
        if not YARA_AVAILABLE:
            raise Exception("YARA library not available. Install with: pip install yara-python")
        
        self.rules_file = rules_file
        self.compiled_rules = None
        self._compile_rules()
    
    def _compile_rules(self):
        """Compile YARA rules from file."""
        try:
            if not Path(self.rules_file).exists():
                raise FileNotFoundError(f"YARA rules file not found: {self.rules_file}")
            
            self.compiled_rules = yara.compile(filepath=self.rules_file)
            
        except yara.Error as e:
            raise Exception(f"YARA compilation error: {e}")
        except Exception as e:
            raise Exception(f"Failed to compile YARA rules: {e}")
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan file with YARA rules.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of YARA match results
        """
        if not self.compiled_rules:
            raise Exception("YARA rules not compiled")
        
        try:
            matches = self.compiled_rules.match(file_path)
            return [
                {
                    "rule_name": match.rule,
                    "metadata": dict(match.meta) if match.meta else {},
                    "tags": list(match.tags) if match.tags else [],
                    "strings": [
                        {
                            "identifier": string.identifier,
                            "instances": len(string.instances)
                        } for string in match.strings
                    ] if match.strings else []
                }
                for match in matches
            ]
            
        except Exception as e:
            raise Exception(f"YARA scanning error: {e}")


class PDFAnalyzer:
    """Main PDF analysis orchestrator combining all detection methods."""
    
    def __init__(self, console_output: bool = True):
        """
        Initialize PDF analyzer.
        
        Args:
            console_output: Whether to enable rich console output // note: removed in v.2.0
        """
        self.string_detector = SuspiciousStringDetector()
    
    def analyze_file(
        self,
        file_path: str,
        yara_rules_file: Optional[str] = None,
        enable_string_detection: bool = True
    ) -> PDFAnalysisResult:
        """
        Perform comprehensive analysis of a single PDF file.
        
        Args:
            file_path: Path to PDF file
            yara_rules_file: Optional YARA rules file path
            enable_string_detection: Whether to perform string detection
            
        Returns:
            PDFAnalysisResult object with all analysis results
        """
        result = PDFAnalysisResult(file_path)
        
        try:
            # Validate file exists
            if not Path(file_path).exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Get file size
            result.file_size = Path(file_path).stat().st_size
            
            # Check if file is actually a PDF
            result.is_pdf = self._verify_pdf_file(file_path)
            
            if not result.is_pdf:
                result.errors.append("File is not a valid PDF")
                return result
            
            # Calculate Shannon entropy
            result.entropy = self._calculate_entropy(file_path)
            
            # Perform string detection (if enabled)
            if enable_string_detection:
                try:
                    result.suspicious_strings = self.string_detector.scan_file(file_path)
                except Exception as e:
                    result.errors.append(f"String detection failed: {e}")
            
            # Perform YARA scanning (if rules provided)
            if yara_rules_file:
                try:
                    yara_scanner = YaraScanner(yara_rules_file)
                    result.yara_matches = yara_scanner.scan_file(file_path)
                except Exception as e:
                    result.errors.append(f"YARA scanning failed: {e}")
                    
        except Exception as e:
            result.errors.append(f"Analysis failed: {e}")
        
        return result
    
    def analyze_directory(
        self,
        directory_path: str,
        yara_rules_file: Optional[str] = None,
        enable_string_detection: bool = True,
        recursive: bool = False
    ) -> List[PDFAnalysisResult]:
        """
        Analyze all PDF files in a directory.
        
        Args:
            directory_path: Path to directory containing PDFs
            yara_rules_file: Optional YARA rules file path
            virustotal_api_key: Optional VirusTotal API key
            enable_string_detection: Whether to perform string detection
            recursive: Whether to scan subdirectories recursively
            
        Returns:
            List of PDFAnalysisResult objects
        """
        results = []
        dir_path = Path(directory_path)
        
        if not dir_path.exists() or not dir_path.is_dir():
            raise ValueError(f"Directory not found: {directory_path}")
        
        # Find PDF files
        pattern = "**/*.pdf" if recursive else "*.pdf"
        pdf_files = list(dir_path.glob(pattern))
        
        if not pdf_files:
            self._print_message(f"No PDF files found in {directory_path}")
            return results
        
        # Analyze each PDF
        for i, pdf_file in enumerate(pdf_files, 1):
            self._print_message(f"Analyzing {i}/{len(pdf_files)}: {pdf_file.name}")
            result = self.analyze_file(
                str(pdf_file),
                yara_rules_file,
                enable_string_detection
            )
            results.append(result)
        
        return results
    
    def _verify_pdf_file(self, file_path: str) -> bool:
        """
        Verify that a file is actually a PDF.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            True if file is a PDF, False otherwise
        """
        try:
            # Method 1: Use python-magic if available
            if MAGIC_AVAILABLE:
                file_type = magic.from_file(file_path)
                return "PDF" in file_type
            
            # Method 2: Check PDF header signature
            with open(file_path, 'rb') as file:
                header = file.read(8)
                return header.startswith(b'%PDF-')
                
        except Exception:
            return False
    
    def _calculate_entropy(self, file_path: str) -> float:
        """
        Calculate Shannon entropy of file content.
        High entropy (e.g. > 7.7) may indicate encrypted/compressed malicious content.
        
        Args:
            file_path: Path to file
            
        Returns:
            Shannon entropy value (0-8, where 8 is maximum entropy)
        """
        
        global riskscore

        try:
            with open(file_path, 'rb') as file:
                data = file.read()
                
            if not data:
                return 0.0
            
            # Count frequency of each byte value
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
                     
            if entropy > 7.7:
                riskscore = riskscore + 1

            return round(entropy, 3)
            
        except Exception as e:
            self._print_message(f"Warning: Could not calculate entropy: {e}")
            return 0.0

    def print_results(self, result: PDFAnalysisResult):
        
        global riskscore

        print(f"\n=== Analysis Results: {result.file_path} ===")
        print(f"Valid PDF: {'Yes' if result.is_pdf else 'No'}")
        print(f"File Size: {result.file_size:,} bytes")
        print(f"Entropy: {result.entropy}/8.0 - {'HIGH' if result.entropy > 7.7 else 'Normal'}") 
        
        if result.suspicious_strings:
            print(f"Suspicious Strings ({len(result.suspicious_strings)}):")
            for match in result.suspicious_strings:
                print(f"  - {match['description']} [{match.get('category', 'UNKNOWN')}]")
        
        if result.yara_matches:
            print(f"YARA Matches ({len(result.yara_matches)}):")
            for match in result.yara_matches:
                print(f"  - {match['rule_name']}")
        
        if result.errors:
            print("Errors:")
            for error in result.errors:
                print(f"  - {error}")
        
        # print(f"Assessment: {'SUSPICIOUS' if result.has_suspicious_content() else 'CLEAN'}")
        print(f"Overall Risk: {riskscore} ")
        print(f"Assessment: {'POTENTIAL HIGH RISK!' if riskscore >= 5  else 'LOW RISK' if riskscore >= 3 else 'NO OBVIOUS THREATS DETECTED'}")
        print()
    
    def _print_message(self, message: str):
        """Print a message using available output method."""
        if self.console:
            self.console.print(message)
        else:
            print(message)

def save_results_to_file(results: Union[PDFAnalysisResult, List[PDFAnalysisResult]], 
                        output_file: str, format_type: str = "json"):
    """
    Save analysis results to file.
    
    Args:
        results: Single result or list of results
        output_file: Output file path
        format_type: Output format ('json' or 'txt')
    """
    global riskscore

    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if isinstance(results, PDFAnalysisResult):
            results = [results]
        
        if format_type.lower() == "json":
            results_data = [result.to_dict() for result in results]
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, default=str)
        else:
            # Simple text format
            with open(output_path, 'w', encoding='utf-8') as f:
                for result in results:
                    f.write(f"File: {result.file_path}\n")
                    f.write(f"PDF: {'Yes' if result.is_pdf else 'No'}\n")
                    f.write(f"Entropy: {result.entropy}\n")
                    #f.write(f"Suspicious: {'Yes' if result.has_suspicious_content() else 'No'}\n")
                    f.write(f"Suspicious: {'Yes' if riskscore >= 5 else 'No'}\n")
                    f.write("-" * 50 + "\n")
                    
    except Exception as e:
        raise Exception(f"Failed to save results to {output_file}: {e}")


def main():

    # reset global variable
    global riskscore
    riskscore = 0 

    # Main CLI entry point.
    parser = argparse.ArgumentParser(
        description="PDFEYE: a PDF Malware Analyzer - (c) Roberto Dillon 2026 - CC-BY-NC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with string detection only
  python pdfeye.py document.pdf

  # Scan a single PDF with YARA
  python pdfeye.py suspicious.pdf --yara pdf_malware_rules.yar

  # Batch scan with YARA
  python pdfeye.py ./pdfs --batch --yara pdf_malware_rules.yar --json

  # Batch scan directory with JSON output
  python pdfeye.py ./pdfs --batch --json --output results.json

  # Recursive directory scan
  python pdfeye.py ./documents --batch --recursive --yara rules.yar

  # Recursive scan with quiet mode
  python pdfeye.py ./documents --batch --recursive --quiet --output scan_results.json
        """
    )
    
    # Positional arguments
    parser.add_argument(
        "target",
        help="PDF file path or directory (use with --batch)"
    )
    
    # Analysis options
    parser.add_argument(
        "--yara",
        help="Path to YARA rules file for advanced pattern matching"
    )
    
    parser.add_argument(
        "--no-strings",
        action="store_true",
        help="Disable suspicious string detection (not recommended)"
    )
    
    # Batch processing
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Process all PDF files in the specified directory"
    )
    
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories (use with --batch)"
    )
    
    # Output options
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    
    parser.add_argument(
        "--output",
        help="Save results to specified file (auto-detects format from extension)"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output (useful with --output)"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate arguments
    if args.recursive and not args.batch:
        parser.error("--recursive can only be used with --batch")
    
    if args.quiet and not args.output:
        parser.error("--quiet requires --output to be specified")
    
    try:
        # Initialize analyzer
        analyzer = PDFAnalyzer(console_output=not args.quiet)
        
        # Perform analysis
        if args.batch:
            results = analyzer.analyze_directory(
                args.target,
                yara_rules_file=args.yara,
                enable_string_detection=not args.no_strings,
                recursive=args.recursive
            )
        else:
            results = [analyzer.analyze_file(
                args.target,
                yara_rules_file=args.yara,
                enable_string_detection=not args.no_strings
            )]
        
        # Handle output
        if args.output:
            # Determine format from file extension
            output_format = "json" if args.output.lower().endswith('.json') else "txt"
            save_results_to_file(results, args.output, output_format)
            
            if not args.quiet:
                analyzer._print_message(f"Results saved to {args.output}")
        
        # Console output (unless quiet mode or JSON output to stdout)
        if not args.quiet:
            if args.json and not args.output:
                # JSON output to stdout
                results_data = [result.to_dict() for result in results]
                print(json.dumps(results_data, indent=2, default=str))
            else:
                for result in results:
                    analyzer.print_results(result)
                
                # Summary for batch operations
                if args.batch and len(results) > 1:
                    suspicious_count = sum(1 for r in results if r.has_suspicious_content())
                    total_count = len(results)
                    analyzer._print_message(
                        f"Batch Analysis Complete: {suspicious_count}/{total_count} files flagged as suspicious"
                    )
        
        # Exit with appropriate code
        suspicious_found = any(result.has_suspicious_content() for result in results)
        sys.exit(1 if suspicious_found else 0)
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
