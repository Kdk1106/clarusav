"""Signed, tamper-evident audit log with SHA-256 hash chaining."""

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class AuditEntry:
    index: int
    timestamp: float
    file_sha256: str
    target_path: str
    verdict: str
    score: float
    deciding_stage: str
    model_version: str
    tau_high: float
    tau_low: float
    prev_hash: str
    entry_hash: str = ""

    def calculate_hash(self) -> str:
        """Compute SHA-256 hash over entry fields including previous entry hash."""
        payload = f"{self.index}|{self.timestamp:.4f}|{self.file_sha256}|{self.target_path}|{self.verdict}|{self.score:.4f}|{self.deciding_stage}|{self.model_version}|{self.tau_high:.4f}|{self.tau_low:.4f}|{self.prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLog:
    """Cryptographic append-only audit log maintaining a verified hash chain."""

    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: Path | str = "/tmp/clarusav/audit.log") -> None:
        self.path = Path(log_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load_entries(self) -> list[AuditEntry]:
        """Read all entries from log file."""
        if not self.path.is_file():
            return []

        entries: list[AuditEntry] = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    entries.append(AuditEntry(**data))
        return entries

    def append(
        self,
        file_sha256: str,
        target_path: str,
        verdict: str,
        score: float,
        deciding_stage: str,
        model_version: str,
        tau_high: float,
        tau_low: float,
    ) -> AuditEntry:
        """Create, hash-link, and append a new audit log entry."""
        entries = self.load_entries()
        prev_hash = entries[-1].entry_hash if entries else self.GENESIS_HASH
        idx = len(entries)

        entry = AuditEntry(
            index=idx,
            timestamp=time.time(),
            file_sha256=file_sha256,
            target_path=str(target_path),
            verdict=verdict,
            score=round(score, 4),
            deciding_stage=deciding_stage,
            model_version=model_version,
            tau_high=round(tau_high, 4),
            tau_low=round(tau_low, 4),
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.calculate_hash()

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

        return entry

    def verify(self) -> tuple[bool, str, int]:
        """Verify the integrity of the cryptographic hash chain.

        Returns:
            Tuple of (is_valid, message, verified_entries_count).
        """
        entries = self.load_entries()
        if not entries:
            return True, "Audit log is empty (valid)", 0

        prev_hash = self.GENESIS_HASH
        for idx, entry in enumerate(entries):
            if entry.index != idx:
                return (
                    False,
                    f"Broken sequence index at entry #{idx} (found index {entry.index})",
                    idx,
                )

            if entry.prev_hash != prev_hash:
                return (
                    False,
                    f"Hash chain broken at entry #{idx}: prev_hash does not match preceding entry",
                    idx,
                )

            expected_hash = entry.calculate_hash()
            if entry.entry_hash != expected_hash:
                return (
                    False,
                    f"Tamper detected at entry #{idx}: recomputed hash does not match stored hash",
                    idx,
                )

            prev_hash = entry.entry_hash

        return (
            True,
            f"Audit log verified successfully ({len(entries)} chained entries)",
            len(entries),
        )
