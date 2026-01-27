import os
import json
import hashlib
import argparse


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


def assess_severity(detected, expected):
    if detected in EXECUTABLE_TYPES and expected not in EXECUTABLE_TYPES:
        return "HIGH"
    if detected != expected:
        return "MEDIUM"
    return "LOW"


def analyze_file(filepath):
    header = read_file_header(filepath)
    detected_type = detect_file_type(header)
    extension = get_extension(filepath)
    expected_type = EXTENSION_MAP.get(extension, "Unknown")

    severity = assess_severity(detected_type, expected_type)
    sha256 = calculate_sha256(filepath)

    suspicious = severity in ["MEDIUM", "HIGH"]

    return {
        "file_path": filepath,
        "extension": extension,
        "detected_type": detected_type,
        "expected_type": expected_type,
        "severity": severity,
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
    print(f"MEDIUM severity: {medium}")

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
