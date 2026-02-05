import os
import json
import hashlib
import argparse
import math


MAGIC_NUMBERS = {
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"%PDF": "PDF Document",
    b"MZ": "Windows Executable",
    b"\x7fELF": "Linux ELF Executable",
}

EXTENSION_MAP = {
    ".png": "PNG Image",
    ".jpg": "JPEG Image",
    ".jpeg": "JPEG Image",
    ".pdf": "PDF Document",
    ".exe": "Windows Executable",
    ".elf": "Linux ELF Executable",
}

EXECUTABLE_TYPES = [
    "Windows Executable",
    "Linux ELF Executable",
]

def read_file_header(filepath, size=16):
    with open(filepath, "rb") as f:
        return f.read(size)


def detect_file_type(header):
    for magic, ftype in MAGIC_NUMBERS.items():
        if header.startswith(magic):
            return ftype
    return "Unknown"


def get_extension(filepath):
    return os.path.splitext(filepath)[1].lower()


def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_entropy(filepath):
    """Calculates the Shannon Entropy of a file."""
    byte_counts = [0] * 256
    total_bytes = 0
    
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):  # Read in 64kb chunks
                total_bytes += len(chunk)
                for byte in chunk:
                    byte_counts[byte] += 1
    except Exception:
        return 0.0

    if total_bytes == 0:
        return 0.0

    entropy = 0
    for count in byte_counts:
        if count == 0:
            continue
        p_x = count / total_bytes
        entropy -= p_x * math.log2(p_x)
    
    return entropy


def assess_severity(detected, expected, entropy):
    if detected in EXECUTABLE_TYPES and expected not in EXECUTABLE_TYPES:
        return "HIGH"
    
    # High entropy (> 7.5) in executables often means packed/encrypted malware
    if detected in EXECUTABLE_TYPES and entropy > 7.5:
        return "HIGH"
        
    if detected != expected:
        return "MEDIUM"
    return "LOW"


def analyze_file(filepath):
    header = read_file_header(filepath)
    detected_type = detect_file_type(header)
    extension = get_extension(filepath)
    expected_type = EXTENSION_MAP.get(extension, "Unknown")

    sha256 = calculate_sha256(filepath)
    entropy = calculate_entropy(filepath)
    
    severity = assess_severity(detected_type, expected_type, entropy)

    suspicious = severity in ["MEDIUM", "HIGH"]

    return {
        "file_path": filepath,
        "extension": extension,
        "detected_type": detected_type,
        "expected_type": expected_type,
        "severity": severity,
        "entropy": round(entropy, 4),
        "sha256": sha256,
        "suspicious": suspicious,
    }

def scan_path(path):
    results = []

    if os.path.isfile(path):
        try:
            results.append(analyze_file(path))
        except Exception:
            pass
        return results

    for root, _, files in os.walk(path):
        for name in files:
            full_path = os.path.join(root, name)
            try:
                results.append(analyze_file(full_path))
            except Exception:
                continue

    return results


def save_json_report(results, output_file):
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)


def print_summary(results):
    high = sum(1 for r in results if r["severity"] == "HIGH")
    medium = sum(1 for r in results if r["severity"] == "MEDIUM")

    print("\n--- Scan Summary ---")
    print(f"Total files scanned: {len(results)}")
    print(f"HIGH severity: {high}")
    print(f"HIGH severity: {high}")
    print(f"MEDIUM severity: {medium}")

    # Highlight high entropy files
    high_entropy_files = [r for r in results if r["entropy"] > 7.5]
    if high_entropy_files:
        print(f"\n[!] Detected {len(high_entropy_files)} files with high entropy (> 7.5).")
        print("    This may indicate packed or encrypted malware.")

    if high > 0:
        print("⚠️  Potential malicious masquerading detected.")

def main():
    parser = argparse.ArgumentParser(
        description="Static File Masquerading Scanner (Magic Number Based)"
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="File or directory to scan"
    )
    parser.add_argument(
        "-o", "--output",
        default="scan_report.json",
        help="Output JSON report file"
    )

    args = parser.parse_args()

    # 🔹 Interactive fallback
    if not args.path:
        args.path = input("Enter file or directory path to scan: ").strip()

    if not os.path.exists(args.path):
        print("❌ Invalid path")
        return

    print(f"[+] Scanning: {args.path}")
    results = scan_path(args.path)

    save_json_report(results, args.output)
    print_summary(results)

    print(f"\n📄 Report saved to: {args.output}")

if __name__ == "__main__":
    main()
