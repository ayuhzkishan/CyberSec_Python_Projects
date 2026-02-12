# File Type Identification & Masquerading Detection Tool

A Python-based cybersecurity tool that detects file types using magic numbers and identifies potential file masquerading attacks. This tool helps security analysts detect malicious files that disguise themselves with misleading file extensions.

## 🎯 Purpose

This tool addresses a common attack vector where malicious files use fake extensions to bypass basic security checks. For example:
- An executable (`.exe`) renamed to look like an image (`.jpg`)
- A malware-laden PDF disguised as a text file
- Packed/encrypted malware with suspiciously high entropy

## 🔍 Core Concepts

### 1. **Magic Numbers (File Signatures)**
Files have unique byte sequences at the beginning that identify their true type, regardless of file extension:

| File Type | Magic Number (Hex) | Description |
|-----------|-------------------|-------------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | PNG image signature |
| JPEG | `FF D8 FF` | JPEG image signature |
| PDF | `25 50 44 46` | PDF document (`%PDF` in ASCII) |
| Windows EXE | `4D 5A` | MZ header (MS-DOS executable) |
| Linux ELF | `7F 45 4C 46` | ELF executable signature |

### 2. **File Entropy Analysis**
Entropy measures the randomness of data in a file:
- **Low Entropy (< 5.0)**: Plain text, structured data
- **Normal Entropy (5.0 - 7.0)**: Compressed files, images
- **High Entropy (> 7.5)**: Encrypted/packed data, potential malware obfuscation

The tool uses **Shannon Entropy** formula:
```
H(X) = -Σ P(x) * log₂(P(x))
```

### 3. **SHA-256 Hashing**
Each file is fingerprinted with SHA-256 hash for:
- File integrity verification
- Malware identification via hash databases (VirusTotal, etc.)
- Forensic evidence tracking

## ⚙️ How It Works

### Workflow Diagram
```
┌─────────────────┐
│  Input File(s)  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ Read File Header (16B)  │  ← Reads first 16 bytes
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Detect File Type        │  ← Compares against magic numbers
│ (via Magic Numbers)     │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Get Expected Type       │  ← Based on file extension
│ (via Extension)         │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Calculate Entropy       │  ← Measures data randomness
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Calculate SHA-256 Hash  │  ← Creates file fingerprint
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Assess Severity Level   │  ← Determines threat level
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Generate JSON Report    │  ← Outputs structured results
└─────────────────────────┘
```

### Key Functions

#### `read_file_header(filepath, size=16)`
Reads the first 16 bytes of a file to examine its magic number.

#### `detect_file_type(header)`
Compares file header against known magic numbers to identify the true file type.

#### `calculate_entropy(filepath)`
Implements Shannon entropy algorithm to detect packed/encrypted content.

#### `assess_severity(detected, expected, entropy)`
Risk assessment logic:
- **HIGH**: Executable masquerading as non-executable OR high entropy executable (> 7.5)
- **MEDIUM**: File type mismatch (extension doesn't match content)
- **LOW**: File is legitimate (extension matches content)

#### `analyze_file(filepath)`
Main analysis function that orchestrates all checks and returns a comprehensive report.

## 📊 Threat Detection Logic

### Severity Levels

```python
if detected_type in EXECUTABLE_TYPES and expected_type not in EXECUTABLE_TYPES:
    severity = "HIGH"  # 🚨 Executable hiding as image/document
    
elif detected_type in EXECUTABLE_TYPES and entropy > 7.5:
    severity = "HIGH"  # 🚨 Highly obfuscated executable (likely packed malware)
    
elif detected_type != expected_type:
    severity = "MEDIUM"  # ⚠️ Extension mismatch (potential masquerading)
    
else:
    severity = "LOW"  # ✅ Legitimate file
```

### Example Scenarios

| Scenario | Extension | Detected Type | Entropy | Severity | Reason |
|----------|-----------|---------------|---------|----------|--------|
| **Malware Masquerading** | `.jpg` | Windows EXE | 6.2 | **HIGH** | Executable disguised as image |
| **Packed Malware** | `.exe` | Windows EXE | 7.8 | **HIGH** | High entropy suggests obfuscation |
| **Extension Mismatch** | `.txt` | PNG Image | 5.1 | **MEDIUM** | Wrong extension, but not executable |
| **Legitimate File** | `.pdf` | PDF Document | 6.5 | **LOW** | Extension matches content |

## 🚀 Usage

### Basic Scan
```bash
python main.py <file_or_directory>
```

### Examples

#### Scan a single file:
```bash
python main.py suspicious_image.jpg
```

#### Scan entire directory:
```bash
python main.py C:\Downloads
```

#### Specify custom output file:
```bash
python main.py C:\Downloads -o malware_scan.json
```

### Interactive Mode
Run without arguments to enter interactive mode:
```bash
python main.py
Enter file or directory path to scan: C:\Users\Documents
```

## 📄 Output Report

### Console Output
```
[+] Scanning: C:\Downloads

--- Scan Summary ---
Total files scanned: 45
HIGH severity: 2
MEDIUM severity: 7

[!] Detected 2 files with high entropy (> 7.5).
    This may indicate packed or encrypted malware.
⚠️  Potential malicious masquerading detected.

📄 Report saved to: scan_report.json
```

### JSON Report Format
```json
[
    {
        "file_path": "C:\\Downloads\\photo.jpg",
        "extension": ".jpg",
        "detected_type": "Windows Executable",
        "expected_type": "JPEG Image",
        "severity": "HIGH",
        "entropy": 7.8432,
        "sha256": "a3b2c1d4e5f6...",
        "suspicious": true
    }
]
```

## 🛡️ Security Use Cases

1. **Malware Detection**: Identify executables with fake extensions
2. **Forensic Analysis**: Examine files from compromised systems
3. **Email Attachment Scanning**: Detect phishing attempts with malicious attachments
4. **Download Verification**: Validate files before execution
5. **Incident Response**: Quickly triage suspicious files

## 🔧 Technical Details

### Supported File Types
- **Images**: PNG, JPEG
- **Documents**: PDF
- **Executables**: Windows PE (.exe), Linux ELF

### Performance Optimizations
- **Chunked Reading**: Processes files in 64KB chunks to handle large files efficiently
- **Recursive Scanning**: Supports directory traversal with exception handling
- **Memory Efficient**: SHA-256 calculated incrementally in 4KB chunks

### Dependencies
```python
import os          # File system operations
import json        # Report generation
import hashlib     # SHA-256 calculation
import argparse    # Command-line interface
import math        # Entropy calculation (log₂)
```

## 🧠 Key Algorithms

### Shannon Entropy Calculation
```python
entropy = -Σ (count/total_bytes) * log₂(count/total_bytes)
```
- Measures information density on a scale of 0-8 bits
- Higher values indicate more randomness/compression

### SHA-256 Hashing
```python
sha256 = hashlib.sha256()
for chunk in file:
    sha256.update(chunk)
return sha256.hexdigest()
```

## 🎓 Learning Outcomes

This project demonstrates:
- **Binary File Analysis**: Reading and interpreting file headers
- **Cryptographic Hashing**: Using SHA-256 for file fingerprinting
- **Information Theory**: Applying Shannon entropy to detect anomalies
- **Malware Detection**: Identifying common obfuscation techniques
- **Python Best Practices**: Modular design, error handling, CLI development

## 📈 Future Enhancements

- [ ] Add support for more file types (ZIP, RAR, Office documents)
- [ ] Integrate with VirusTotal API for hash-based scanning
- [ ] Implement YARA rules for advanced pattern matching
- [ ] Add real-time directory monitoring
- [ ] Create GUI interface
- [ ] Export reports in multiple formats (CSV, HTML)

## ⚠️ Limitations

- **Static Analysis Only**: Does not execute or dynamically analyze files
- **Limited File Type Coverage**: Only checks common file signatures
- **False Positives**: Compressed/encrypted legitimate files may trigger high entropy warnings
- **Magic Number Database**: Only includes basic file type signatures

## 📝 License

This is an educational cybersecurity tool for learning purposes.

## 🤝 Contributing

Feel free to extend the magic number database or add new detection techniques!

---

**Note**: Always combine this tool with other security measures. Static analysis alone cannot detect all malware variants.
