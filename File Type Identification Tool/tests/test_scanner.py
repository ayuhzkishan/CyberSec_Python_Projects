"""
Tests for the File Type Identification & Masquerading Detection Tool.

Run with:
    pytest tests/test_scanner.py -v
"""

import sys
import os
import json
import hashlib

import pytest

# Allow imports from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import (
    detect_file_type,
    assess_severity,
    calculate_sha256,
    calculate_entropy,
    analyze_file,
    scan_path,
)


# ---------------------------------------------------------------------------
# detect_file_type
# ---------------------------------------------------------------------------

class TestDetectFileType:
    """Magic-number based type detection."""

    @pytest.mark.parametrize("header, expected", [
        (b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "PNG Image"),
        (b"\xff\xd8\xff\xe0" + b"\x00" * 20,  "JPEG Image"),
        (b"GIF89a" + b"\x00" * 20,             "GIF Image"),
        (b"GIF87a" + b"\x00" * 20,             "GIF Image"),
        (b"BM" + b"\x00" * 20,                 "BMP Image"),
        (b"%PDF-1.4" + b"\x00" * 20,           "PDF Document"),
        (b"PK\x03\x04" + b"\x00" * 20,        "ZIP / Office Open XML"),
        (b"Rar!\x1a\x07" + b"\x00" * 20,      "RAR Archive"),
        (b"ID3" + b"\x00" * 20,                "MP3 Audio"),
        (b"\xff\xfb" + b"\x00" * 20,           "MP3 Audio"),
        (b"MZ" + b"\x00" * 20,                 "Windows Executable"),
        (b"\x7fELF" + b"\x00" * 20,            "Linux ELF Executable"),
        (b"\xca\xfe\xba\xbe" + b"\x00" * 20,  "Java Class Bytecode"),
        (b"\xde\xad\xbe\xef" + b"\x00" * 20,  "Unknown"),  # unrecognised bytes
    ])
    def test_known_magic_bytes(self, header, expected):
        assert detect_file_type(header) == expected

    def test_empty_header_returns_unknown(self):
        assert detect_file_type(b"") == "Unknown"

    def test_mp4_ftyp_variant(self):
        header = b"\x00\x00\x00\x18ftyp" + b"\x00" * 20
        assert detect_file_type(header) == "MP4 Video"


# ---------------------------------------------------------------------------
# assess_severity
# ---------------------------------------------------------------------------

class TestAssessSeverity:
    """Threat severity logic."""

    def test_exe_disguised_as_jpg_is_high(self):
        assert assess_severity("Windows Executable", "JPEG Image", 5.0) == "HIGH"

    def test_elf_disguised_as_pdf_is_high(self):
        assert assess_severity("Linux ELF Executable", "PDF Document", 4.0) == "HIGH"

    def test_java_class_disguised_as_png_is_high(self):
        assert assess_severity("Java Class Bytecode", "PNG Image", 4.0) == "HIGH"

    def test_high_entropy_executable_is_high(self):
        # Executable that looks like an executable but is packed (entropy > 7.5)
        assert assess_severity("Windows Executable", "Windows Executable", 7.9) == "HIGH"

    def test_extension_mismatch_is_medium(self):
        # PNG bytes but .txt extension
        assert assess_severity("PNG Image", "Unknown", 5.0) == "MEDIUM"

    def test_legitimate_file_is_low(self):
        assert assess_severity("PDF Document", "PDF Document", 6.5) == "LOW"

    def test_legitimate_exe_low_entropy_is_low(self):
        assert assess_severity("Windows Executable", "Windows Executable", 5.0) == "LOW"


# ---------------------------------------------------------------------------
# calculate_sha256
# ---------------------------------------------------------------------------

class TestCalculateSha256:
    """SHA-256 fingerprinting."""

    def test_known_hash(self, tmp_path):
        data = b"hello world"
        f = tmp_path / "sample.txt"
        f.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert calculate_sha256(str(f)) == expected

    def test_empty_file_hash(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert calculate_sha256(str(f)) == expected


# ---------------------------------------------------------------------------
# calculate_entropy
# ---------------------------------------------------------------------------

class TestCalculateEntropy:
    """Shannon entropy calculation."""

    def test_uniform_bytes_max_entropy(self, tmp_path):
        """All 256 distinct bytes → entropy close to 8.0."""
        data = bytes(range(256)) * 64          # 16 KB of perfectly uniform data
        f = tmp_path / "uniform.bin"
        f.write_bytes(data)
        entropy = calculate_entropy(str(f))
        assert entropy > 7.9

    def test_repeated_byte_low_entropy(self, tmp_path):
        """Single repeated byte → entropy of 0.0."""
        f = tmp_path / "zeros.bin"
        f.write_bytes(b"\x00" * 4096)
        assert calculate_entropy(str(f)) == 0.0

    def test_plain_text_moderate_entropy(self, tmp_path):
        """Plain ASCII text should have moderate entropy (2-6)."""
        f = tmp_path / "text.txt"
        f.write_bytes(b"hello world this is a test " * 100)
        entropy = calculate_entropy(str(f))
        assert 2.0 < entropy < 6.0

    def test_empty_file_entropy(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert calculate_entropy(str(f)) == 0.0


# ---------------------------------------------------------------------------
# analyze_file  (integration)
# ---------------------------------------------------------------------------

class TestAnalyzeFile:
    """End-to-end file analysis results."""

    def test_legitimate_png_is_low_severity(self, tmp_path):
        f = tmp_path / "photo.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        result = analyze_file(str(f))
        assert result["detected_type"] == "PNG Image"
        assert result["severity"] == "LOW"
        assert result["suspicious"] is False

    def test_exe_disguised_as_jpg_is_high_severity(self, tmp_path):
        f = tmp_path / "totally_safe.jpg"
        f.write_bytes(b"MZ" + b"\x00" * 100)   # PE header, .jpg extension
        result = analyze_file(str(f))
        assert result["detected_type"] == "Windows Executable"
        assert result["severity"] == "HIGH"
        assert result["suspicious"] is True

    def test_result_contains_all_expected_keys(self, tmp_path):
        f = tmp_path / "test.pdf"
        f.write_bytes(b"%PDF-1.4" + b"\x00" * 50)
        result = analyze_file(str(f))
        for key in ("file_path", "extension", "detected_type",
                    "expected_type", "severity", "entropy", "sha256", "suspicious"):
            assert key in result

    def test_sha256_in_result_is_valid_hex(self, tmp_path):
        f = tmp_path / "file.pdf"
        f.write_bytes(b"%PDF-1.4" + b"\x00" * 50)
        result = analyze_file(str(f))
        assert len(result["sha256"]) == 64
        int(result["sha256"], 16)   # raises ValueError if not valid hex


# ---------------------------------------------------------------------------
# scan_path
# ---------------------------------------------------------------------------

class TestScanPath:
    """Directory and file scanning."""

    def test_scan_single_file(self, tmp_path):
        f = tmp_path / "legit.pdf"
        f.write_bytes(b"%PDF-1.4" + b"\x00" * 50)
        results = scan_path(str(f))
        assert len(results) == 1

    def test_scan_directory(self, tmp_path):
        (tmp_path / "a.pdf").write_bytes(b"%PDF-1.4" + b"\x00" * 50)
        (tmp_path / "b.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
        (tmp_path / "c.jpg").write_bytes(b"MZ" + b"\x00" * 50)   # suspicious
        results = scan_path(str(tmp_path))
        assert len(results) == 3
        high = [r for r in results if r["severity"] == "HIGH"]
        assert len(high) == 1

    def test_scan_empty_directory(self, tmp_path):
        results = scan_path(str(tmp_path))
        assert results == []
