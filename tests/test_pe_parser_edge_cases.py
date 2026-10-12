"""Unit tests for PE parser edge cases: empty, non-PE, truncated, huge files."""

import struct
from pathlib import Path

import pytest

from clarusav.config import ClarusConfig, FeaturesConfig
from clarusav.features.extractor import (
    EmptyFileError,
    FileTooLargeError,
    LivePEFeatureExtractor,
    NotAPEFileError,
    TruncatedPEError,
)
from tests.conftest import build_synthetic_pe


def test_empty_file_in_memory():
    """Empty byte buffer (0 bytes) must raise EmptyFileError."""
    extractor = LivePEFeatureExtractor()
    with pytest.raises(EmptyFileError, match="empty"):
        extractor.extract_from_bytes(b"")


def test_empty_file_on_disk(tmp_path: Path):
    """Empty file on disk must raise EmptyFileError."""
    empty_file = tmp_path / "empty.exe"
    empty_file.write_bytes(b"")

    extractor = LivePEFeatureExtractor()
    with pytest.raises(EmptyFileError, match="empty"):
        extractor.extract_from_file(empty_file)


def test_nonexistent_file(tmp_path: Path):
    """Missing file must raise FileNotFoundError."""
    extractor = LivePEFeatureExtractor()
    with pytest.raises(FileNotFoundError):
        extractor.extract_from_file(tmp_path / "does_not_exist.exe")


@pytest.mark.parametrize(
    "payload,desc",
    [
        (b"Plain text file with no MZ header", "plain_text"),
        (b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00", "elf_binary"),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00", "jpeg_image"),
        (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "png_image"),
        (b"\x00" * 128, "null_bytes"),
    ],
)
def test_non_pe_files(payload: bytes, desc: str):
    """Files without MZ DOS signature must raise NotAPEFileError."""
    extractor = LivePEFeatureExtractor()
    with pytest.raises(NotAPEFileError):
        extractor.extract_from_bytes(payload)


def test_truncated_pe_dos_stub_only():
    """File consisting only of 'MZ' or truncated DOS header must fail safely."""
    extractor = LivePEFeatureExtractor()
    with pytest.raises((NotAPEFileError, TruncatedPEError)):
        extractor.extract_from_bytes(b"MZ")

    with pytest.raises((NotAPEFileError, TruncatedPEError)):
        extractor.extract_from_bytes(b"MZ" + b"\x00" * 20)


def test_truncated_pe_invalid_lfanew():
    """e_lfanew pointing out of file bounds must raise TruncatedPEError."""
    dos_hdr = bytearray(64)
    dos_hdr[:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, 0x10000)  # Points to 64KB, file is 64 bytes

    extractor = LivePEFeatureExtractor()
    with pytest.raises((TruncatedPEError, NotAPEFileError)):
        extractor.extract_from_bytes(bytes(dos_hdr))


def test_truncated_pe_cut_off_at_coff():
    """PE signature present but truncated before COFF header completes."""
    dos_hdr = bytearray(64)
    dos_hdr[:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, 64)
    truncated = bytes(dos_hdr) + b"PE\x00\x00\x01\x02"  # 6 bytes after signature

    extractor = LivePEFeatureExtractor()
    with pytest.raises(TruncatedPEError):
        extractor.extract_from_bytes(truncated)


def test_truncated_pe_missing_sections():
    """Valid headers declaring sections, but binary truncated before section data."""
    valid_pe = build_synthetic_pe(sections=[(".text", b"\x90" * 0x200)])
    # Truncate halfway into headers
    truncated = valid_pe[:0x150]

    extractor = LivePEFeatureExtractor()
    with pytest.raises(TruncatedPEError):
        extractor.extract_from_bytes(truncated)


def test_huge_file_limit_in_memory():
    """Payload exceeding max_file_size_bytes must raise FileTooLargeError."""
    # Configure a small size limit for fast testing
    cfg = ClarusConfig(features=FeaturesConfig(max_file_size_bytes=1024))
    extractor = LivePEFeatureExtractor(config=cfg)

    oversized_data = b"MZ" + b"\x00" * 2048
    with pytest.raises(FileTooLargeError, match="exceeds maximum allowed limit"):
        extractor.extract_from_bytes(oversized_data)


def test_huge_file_limit_on_disk(tmp_path: Path):
    """File on disk exceeding max_file_size_bytes must be rejected before parsing."""
    cfg = ClarusConfig(features=FeaturesConfig(max_file_size_bytes=512))
    extractor = LivePEFeatureExtractor(config=cfg)

    large_file = tmp_path / "large.exe"
    large_file.write_bytes(b"MZ" + b"\x00" * 1024)

    with pytest.raises(FileTooLargeError, match="exceeds maximum allowed limit"):
        extractor.extract_from_file(large_file)
