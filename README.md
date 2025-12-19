# PDFEYE - a PDF Malware Analyzer 
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
