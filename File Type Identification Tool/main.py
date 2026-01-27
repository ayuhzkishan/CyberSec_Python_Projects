import os

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

def read_file_header(filepath, num_bytes=16):
    """Read the first bytes of a file (binary header)."""
    with open(filepath, "rb") as f:
        return f.read(num_bytes)


def detect_file_type(header_bytes):
    """Detect real file type using magic numbers."""
    for magic, filetype in MAGIC_NUMBERS.items():
        if header_bytes.startswith(magic):
            return filetype
    return "Unknown"


def get_extension(filepath):
    """Extract file extension."""
    return os.path.splitext(filepath)[1].lower()


def analyze_file(filepath):
    """Analyze file and detect extension mismatch."""
    header = read_file_header(filepath)
    detected_type = detect_file_type(header)

    extension = get_extension(filepath)
    expected_type = EXTENSION_MAP.get(extension, "Unknown")

    suspicious = False
    if detected_type != "Unknown" and expected_type != "Unknown":
        if detected_type != expected_type:
            suspicious = True

    return {
        "file": filepath,
        "extension": extension,
        "detected_type": detected_type,
        "expected_type": expected_type,
        "suspicious": suspicious,
    }


def main():
    filepath = input("Enter file path: ").strip()

    if not os.path.isfile(filepath):
        print("❌ Error: File does not exist.")
        return

    result = analyze_file(filepath)

    print("\n--- File Analysis Report ---")
    print(f"File: {result['file']}")
    print(f"Extension: {result['extension']}")
    print(f"Detected Type: {result['detected_type']}")
    print(f"Expected Type: {result['expected_type']}")

    if result["suspicious"]:
        print("⚠️ WARNING: File type mismatch detected!")
    else:
        print("✅ File type matches extension.")


if __name__ == "__main__":
    main()
