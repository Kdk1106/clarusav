"""Quarantine management for safely isolating and restoring malicious binaries."""

import hashlib
import json
import os
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class QuarantineRecord:
    item_id: str
    original_path: str
    quarantine_path: str
    sha256: str
    file_size: int
    timestamp: float
    reason: str
    restored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class QuarantineManager:
    """Manages secure file isolation, storage, manifest tracking, and restoration."""

    def __init__(self, quarantine_dir: Path | str = "/tmp/clarusav/quarantine") -> None:
        self.vault_dir = Path(quarantine_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.vault_dir / "manifest.json"

    def _load_manifest(self) -> dict[str, dict[str, Any]]:
        if not self.manifest_path.is_file():
            return {}
        try:
            with open(self.manifest_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_manifest(self, data: dict[str, dict[str, Any]]) -> None:
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def quarantine(self, target_file: Path | str, reason: str = "MALICIOUS") -> QuarantineRecord:
        """Move a malicious file into the quarantine vault, removing host execute permissions."""
        src = Path(target_file).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Target file for quarantine does not exist: {src}")

        with open(src, "rb") as f:
            content = f.read()
        file_hash = hashlib.sha256(content).hexdigest()
        item_id = file_hash[:16]

        quarantined_name = f"{item_id}.quarantine"
        dest = self.vault_dir / quarantined_name

        # Copy and remove permissions, then unlink original
        shutil.copy2(src, dest)
        os.chmod(dest, 0o600)  # Read/write for owner only, no execute
        src.unlink()

        record = QuarantineRecord(
            item_id=item_id,
            original_path=str(src),
            quarantine_path=str(dest),
            sha256=file_hash,
            file_size=len(content),
            timestamp=time.time(),
            reason=reason,
            restored=False,
        )

        manifest = self._load_manifest()
        manifest[item_id] = record.to_dict()
        self._save_manifest(manifest)

        return record

    def restore(self, item_id: str) -> Path:
        """Restore a quarantined binary to its original location."""
        manifest = self._load_manifest()
        if item_id not in manifest:
            raise KeyError(f"Quarantine item not found: {item_id}")

        info = manifest[item_id]
        if info.get("restored"):
            raise ValueError(f"Item {item_id} has already been restored.")

        q_path = Path(info["quarantine_path"])
        orig_path = Path(info["original_path"])

        if not q_path.is_file():
            raise FileNotFoundError(f"Quarantined file missing from vault: {q_path}")

        orig_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(q_path, orig_path)
        q_path.unlink()

        manifest[item_id]["restored"] = True
        self._save_manifest(manifest)

        return orig_path

    def list_records(self) -> list[QuarantineRecord]:
        """List all quarantined files."""
        manifest = self._load_manifest()
        records: list[QuarantineRecord] = []
        for d in manifest.values():
            records.append(QuarantineRecord(**d))
        return records
