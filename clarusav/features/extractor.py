"""Live PE feature extractor computing security ML features from Windows binaries."""

import os
import time
from pathlib import Path

import pefile

from clarusav.config import ClarusConfig, load_config
from clarusav.features.entropy import calculate_entropy
from clarusav.features.registry import FeatureRegistry, default_registry


class PEParserError(Exception):
    """Base exception for PE parsing failures."""

    pass


class EmptyFileError(PEParserError):
    """Raised when the target file is empty (0 bytes)."""

    pass


class FileTooLargeError(PEParserError):
    """Raised when the target file exceeds the configured maximum size limit."""

    pass


class NotAPEFileError(PEParserError):
    """Raised when the target file does not contain a valid PE DOS header / magic."""

    pass


class TruncatedPEError(PEParserError):
    """Raised when the PE structure is truncated or corrupted."""

    pass


class LivePEFeatureExtractor:
    """Extracts ML features directly from real Windows PE files on disk or in memory."""

    def __init__(
        self,
        config: ClarusConfig | None = None,
        registry: FeatureRegistry | None = None,
    ) -> None:
        self.config = config or load_config()
        self.registry = registry or default_registry
        self.suspicious_watchlist: set[str] = {
            s.lower() for s in self.config.features.suspicious_imports
        }

    def check_file_constraints(self, size: int) -> None:
        """Validate basic file size constraints."""
        if size == 0:
            raise EmptyFileError("File is empty (0 bytes).")
        max_size = self.config.features.max_file_size_bytes
        if size > max_size:
            raise FileTooLargeError(
                f"File size ({size} bytes) exceeds maximum allowed limit ({max_size} bytes)."
            )

    def extract_from_bytes(
        self,
        data: bytes,
        reference_time: float | None = None,
    ) -> dict[str, float]:
        """Extract features from raw bytes of a PE binary.

        Args:
            data: Raw file bytes.
            reference_time: Optional epoch timestamp for timestamp anomaly evaluation.

        Returns:
            Dictionary mapping feature names to extracted float values.
        """
        self.check_file_constraints(len(data))

        if len(data) < 2 or data[:2] != b"MZ":
            raise NotAPEFileError("File does not start with DOS 'MZ' signature.")

        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as e:
            msg = str(e)
            if "DOS Header magic not found" in msg or "NT Headers not found" in msg:
                raise NotAPEFileError(f"Invalid PE structure: {msg}") from e
            raise TruncatedPEError(f"Corrupted or truncated PE binary: {msg}") from e
        except Exception as e:
            raise TruncatedPEError(f"Failed to parse PE binary: {e}") from e

        try:
            return self._extract_pe_features(pe, file_size=len(data), reference_time=reference_time)
        finally:
            pe.close()

    def extract_from_file(
        self,
        file_path: str | Path,
        reference_time: float | None = None,
    ) -> dict[str, float]:
        """Extract features from a PE file on disk.

        Args:
            file_path: Path to PE binary.
            reference_time: Optional epoch timestamp for timestamp anomaly evaluation.

        Returns:
            Dictionary mapping feature names to extracted float values.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        file_size = os.path.getsize(path)
        self.check_file_constraints(file_size)

        with open(path, "rb") as f:
            data = f.read()

        return self.extract_from_bytes(data, reference_time=reference_time)

    def _extract_pe_features(
        self,
        pe: pefile.PE,
        file_size: int,
        reference_time: float | None = None,
    ) -> dict[str, float]:
        """Extract the canonical 6 features from a parsed pefile.PE object."""
        # 1. file_size
        feat_file_size = float(file_size)

        # 2. section_count
        sections = getattr(pe, "sections", []) or []
        feat_section_count = float(len(sections))

        # 3. max_section_entropy
        section_entropies: list[float] = []
        for sec in sections:
            sec_data = sec.get_data() if hasattr(sec, "get_data") else b""
            section_entropies.append(calculate_entropy(sec_data))
        feat_max_entropy = float(max(section_entropies, default=0.0))

        # 4. import_count & 5. suspicious_import_count
        import_count = 0
        suspicious_count = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_count += 1
                    func_name: str | None = None
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore").strip().lower()
                    if func_name and func_name in self.suspicious_watchlist:
                        suspicious_count += 1

        feat_import_count = float(import_count)
        feat_suspicious_import_count = float(suspicious_count)

        # 6. timestamp_anomaly
        timestamp = 0
        if hasattr(pe, "FILE_HEADER") and hasattr(pe.FILE_HEADER, "TimeDateStamp"):
            timestamp = pe.FILE_HEADER.TimeDateStamp

        feat_timestamp_anomaly = float(self.compute_timestamp_anomaly(timestamp, reference_time))

        features = {
            "file_size": feat_file_size,
            "section_count": feat_section_count,
            "max_section_entropy": feat_max_entropy,
            "import_count": feat_import_count,
            "suspicious_import_count": feat_suspicious_import_count,
            "timestamp_anomaly": feat_timestamp_anomaly,
        }

        return features

    def compute_timestamp_anomaly(
        self,
        timestamp: int,
        reference_time: float | None = None,
    ) -> int:
        """Determine if a PE timestamp is anomalous."""
        min_ts = self.config.features.timestamp.min_timestamp
        ref = reference_time if reference_time is not None else time.time()
        max_ts = int(ref + self.config.features.timestamp.future_tolerance_seconds)

        if timestamp == 0 or timestamp < min_ts or timestamp > max_ts:
            return 1
        return 0

    def extract_vector(
        self,
        file_path_or_bytes: str | Path | bytes,
        reference_time: float | None = None,
    ) -> list[float]:
        """Extract ordered feature vector corresponding to canonical registry order."""
        if isinstance(file_path_or_bytes, bytes):
            feat_map = self.extract_from_bytes(file_path_or_bytes, reference_time=reference_time)
        else:
            feat_map = self.extract_from_file(file_path_or_bytes, reference_time=reference_time)

        return [feat_map[name] for name in self.registry.feature_names]
