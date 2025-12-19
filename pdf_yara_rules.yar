/*
    PDFeye Malware Detection YARA Rules
    =================================
    
    A collection of YARA rules for detecting suspicious and malicious
    PDF files. These rules can be used with the PDFeye Analyzer tool.
    
    Usage:
        python pdf_analyzer.py document.pdf --yara pdf_rules.yar
    
    Rules included:
    - PDF_JavaScript_Embedded: Detects JavaScript code in PDFs
    - PDF_AutoAction: Detects auto-execution triggers
    - PDF_Suspicious_Launch: Detects external application launch
    - PDF_Obfuscated_Content: Detects potential obfuscation techniques
    - PDF_Form_Submission: Detects forms that submit data externally
    - PDF_Embedded_Executable: Detects embedded executable files
    - PDF_High_Entropy_Stream: Detects highly compressed/encrypted streams
    - PDF_Shellcode_Indicators: Detects potential shellcode patterns
*/

rule PDF_JavaScript_Embedded
{
    meta:
        description = "Detects PDF files containing embedded JavaScript code"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "medium"
        category = "suspicious"
        
    strings:
        // PDF header
        $pdf_header = "%PDF-" 
        
        // JavaScript indicators
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $js3 = "app.alert" nocase
        $js4 = "app.launchURL" nocase
        $js5 = "util.printf" nocase
        
        // Common JavaScript API calls
        $api1 = "getField" nocase
        $api2 = "submitForm" nocase
        
    condition:
        $pdf_header at 0 and 
        (
            ($js1 or $js2) and 
            any of ($js3, $js4, $js5, $api1, $api2)
        )
}

rule PDF_AutoAction
{
    meta:
        description = "Detects PDF files with automatic action triggers"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "high"
        category = "suspicious"
        reference = "Auto-execution is commonly used in PDF malware"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Auto-action triggers
        $aa = "/AA" nocase
        $openaction = "/OpenAction" nocase
        $names = "/Names" nocase
        
        // Combined with JavaScript
        $js = "/JavaScript" nocase
        
    condition:
        $pdf_header at 0 and 
        (
            ($aa or $openaction) and 
            ($js or $names)
        )
}

rule PDF_Suspicious_Launch
{
    meta:
        description = "Detects PDF files attempting to launch external applications"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "high"
        category = "malicious"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Launch actions
        $launch = "/Launch" nocase
        $win = "/Win" nocase
        $f = "/F" nocase
        
        // Suspicious executables
        $exe1 = ".exe" nocase
        $exe2 = ".bat" nocase
        $exe3 = ".cmd" nocase
        $exe4 = ".com" nocase
        $exe5 = ".scr" nocase
        $exe6 = ".vbs" nocase
        $exe7 = ".ps1" nocase
        
        // System commands
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "wscript" nocase
        
    condition:
        $pdf_header at 0 and 
        $launch and 
        (
            any of ($exe*) or 
            any of ($cmd*) or
            $win or
            $f
        )
}

rule PDF_Obfuscated_Content
{
    meta:
        description = "Detects PDF files with multiple layers of obfuscation"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "medium"
        category = "suspicious"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Obfuscation techniques
        $objstm = "/ObjStm" nocase
        $filter1 = "/ASCIIHexDecode" nocase
        $filter2 = "/ASCII85Decode" nocase
        $filter3 = "/LZWDecode" nocase
        $filter4 = "/RunLengthDecode" nocase
        
        // Multiple encoding layers (suspicious)
        $flate = "/FlateDecode" nocase
        
        // JavaScript with encoding
        $js = "/JavaScript" nocase
        
    condition:
        $pdf_header at 0 and 
        (
            (#objstm > 5) or 
            (
                $js and 
                (
                    any of ($filter*) or 
                    (#flate > 10)
                )
            )
        )
}

rule PDF_Form_Submission
{
    meta:
        description = "Detects PDF forms configured to submit data to external URLs"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "medium"
        category = "suspicious"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Form elements
        $acroform = "/AcroForm" nocase
        $submitform = "/SubmitForm" nocase
        $uri = "/URI" nocase
        
        // Network protocols
        $http = "http://" nocase
        $https = "https://" nocase
        $ftp = "ftp://" nocase
        
    condition:
        $pdf_header at 0 and 
        (
            ($acroform and $submitform) or 
            ($submitform and ($http or $https or $ftp)) or
            ($acroform and $uri and ($http or $https or $ftp))
        )
}

rule PDF_Embedded_Executable
{
    meta:
        description = "Detects PDF files with embedded executable content"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "high"
        category = "malicious"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Embedded file indicators
        $embedded = "/EmbeddedFile" nocase
        $filespec = "/FileSpec" nocase
        
        // PE file signatures (Windows executables)
        $mz_header = "MZ"
        $pe_header = "PE\x00\x00"
        
        // ELF file signature (Linux executables)
        $elf_header = { 7F 45 4C 46 }
        
        // JAR/ZIP signatures (Java executables)
        $zip_header = "PK\x03\x04"
        
    condition:
        $pdf_header at 0 and 
        (
            ($embedded or $filespec) and 
            (
                $mz_header or 
                $pe_header or 
                $elf_header or 
                $zip_header
            )
        )
}

rule PDF_High_Entropy_Stream
{
    meta:
        description = "Detects PDF streams with high entropy (potential encryption/packing)"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "low"
        category = "suspicious"
        reference = "High entropy may indicate encrypted shellcode or packed malware"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Stream objects
        $stream_start = "stream"
        $stream_end = "endstream"
        
        // Look for streams with minimal repeating patterns (high randomness)
        $flate = "/FlateDecode" nocase
        
    condition:
        $pdf_header at 0 and 
        (#stream_start > 20) and 
        (#flate > 15) and
        $stream_end
}

rule PDF_Shellcode_Indicators
{
    meta:
        description = "Detects potential shellcode patterns in PDF files"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "high"
        category = "malicious"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Stream indicators
        $stream_start = "stream"
        
        // Common shellcode patterns (NOP sleds, etc.)
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        
        // x86 shellcode common instructions
        $call_pop = { E8 ?? ?? ?? ?? 5? }  // call/pop technique
        $jmp_call = { EB ?? E8 }           // jmp/call technique
        
        // String manipulation (common in exploits)
        $string_decode = "String.fromCharCode" nocase
        $unescape = "unescape" nocase
        $eval = "eval(" nocase
        
        // Heap spray indicators
        $heap_spray1 = { 0C 0C 0C 0C 0C 0C 0C 0C }
        $heap_spray2 = "%u0c0c" nocase
        
    condition:
        $pdf_header at 0 and 
        (
            $nop_sled or 
            $call_pop or 
            $jmp_call or 
            (
                2 of ($string_decode, $unescape, $eval) and 
                $stream_start
            ) or
            $heap_spray1 or 
            $heap_spray2
        )
}

rule PDF_XFA_Forms
{
    meta:
        description = "Detects PDF files using XFA (XML Forms Architecture)"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "low"
        category = "informational"
        reference = "XFA forms have been exploited in the past"
        
    strings:
        $pdf_header = "%PDF-"
        $xfa = "/XFA" nocase
        $xml = "<?xml" nocase
        
    condition:
        $pdf_header at 0 and 
        $xfa and 
        $xml
}

rule PDF_URI_External_Content
{
    meta:
        description = "Detects PDF files with external URI references"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "low"
        category = "suspicious"
        
    strings:
        $pdf_header = "%PDF-"
        
        // URI action
        $uri_action = "/URI" nocase
        
        // Suspicious domains/IPs - using simple patterns
        $http = "http://" nocase
        $https = "https://" nocase
        
        // Shortened URLs (commonly used in phishing)
        $shorturl1 = "bit.ly" nocase
        $shorturl2 = "tinyurl" nocase
        $shorturl3 = "goo.gl" nocase
        
    condition:
        $pdf_header at 0 and 
        $uri_action and 
        (
            $http or
            $https or
            any of ($shorturl*)
        )
}

rule PDF_CVE_Exploit_Indicators
{
    meta:
        description = "Detects common patterns associated with PDF exploits"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "high"
        category = "exploit"
        reference = "Generic exploit detection patterns"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Stream indicators
        $stream_start = "stream"
        
        // CVE-2013-2729 (Buffer overflow in XFA)
        $xfa_overflow = "/XFA" nocase
        
        // CVE-2010-0188 (LibTIFF vulnerability)
        $tiff = "TIFF" nocase
        $ccitt = "/CCITTFaxDecode" nocase
        
        // CVE-2009-0927 (JBIG2Decode vulnerability)
        $jbig2 = "/JBIG2Decode" nocase
        
        // Suspicious JavaScript patterns
        $js_vuln1 = "util.printf" nocase
        $js_vuln2 = "Collab.collectEmailInfo" nocase
        $js_vuln3 = "media.newPlayer" nocase
        
        // Large array allocations (heap spray)
        $array = "new Array" nocase
        
    condition:
        $pdf_header at 0 and 
        (
            ($xfa_overflow and #array > 3) or
            ($tiff and $ccitt) or
            ($jbig2 and (#stream_start > 10)) or
            any of ($js_vuln*)
        )
}

rule PDF_Multiple_Suspicious_Elements
{
    meta:
        description = "Detects PDFs with multiple suspicious elements combined"
        author = "PDF Security Analyzer"
        date = "2024-12-17"
        severity = "high"
        category = "suspicious"
        
    strings:
        $pdf_header = "%PDF-"
        
        // Multiple suspicious indicators
        $js = "/JavaScript" nocase
        $aa = "/AA" nocase
        $openaction = "/OpenAction" nocase
        $launch = "/Launch" nocase
        $uri = "/URI" nocase
        $embedded = "/EmbeddedFile" nocase
        $objstm = "/ObjStm" nocase
        
    condition:
        $pdf_header at 0 and 
        (
            // 3 or more suspicious elements
            (
                (uint8(0) == 0x25 and uint8(1) == 0x50) and  // %P
                (
                    ($js and ($aa or $openaction)) or
                    ($js and ($launch or $uri)) or
                    ($embedded and ($js or $launch)) or
                    (#objstm > 10 and $js)
                )
            )
        )
}

/*
    Rule Usage Notes:
    -----------------
    
    1. Save these rules to a file (e.g., pdf_malware_rules.yar)
    
    2. Use with the PDF analyzer:
       python pdfeye.py suspicious.pdf --yara pdf_malware_rules.yar
    
    3. Batch scanning:
       python pdfeye.py ./documents --batch --yara pdf_malware_rules.yar --json
    
    Rule Severity Levels:
    - low: Informational, may be legitimate
    - medium: Suspicious, requires review
    - high: Likely malicious, immediate review needed
    
    False Positives:
    - Interactive PDFs may trigger JavaScript rules
    - Forms with external submission may be legitimate
    - High entropy is normal for compressed content
    
    Always validate findings manually before taking action!
*/