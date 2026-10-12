"""Fast path SHA-256 allow/deny cache keyed by model version."""

import json
import time
from pathlib import Path
from typing import Any


class FastPathCache:
    """Persistent SHA-256 cache that allows repeat files to bypass model inference."""

    def __init__(self, cache_file: Path | str = "/tmp/clarusav/cache.json") -> None:
        self.path = Path(cache_file)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.is_file():
            return {}
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception:
            pass

    def get(self, sha256: str, model_version: str) -> dict[str, Any] | None:
        """Lookup cached verdict keyed by file SHA-256 and model version."""
        entry = self._data.get(sha256.lower())
        if not entry:
            return None

        # Verify model version matches (cache invalidation on model update)
        if entry.get("model_version") != model_version:
            return None

        return entry

    def set(
        self,
        sha256: str,
        model_version: str,
        verdict: str,
        score: float,
        band_position: str,
        deciding_stage: str,
    ) -> None:
        """Store verdict in fast-path cache."""
        self._data[sha256.lower()] = {
            "sha256": sha256.lower(),
            "model_version": model_version,
            "verdict": verdict,
            "score": round(score, 4),
            "band_position": band_position,
            "deciding_stage": deciding_stage,
            "cached_at": time.time(),
        }
        self._save()

    def clear(self) -> None:
        """Clear cache storage."""
        self._data = {}
        self._save()

    def __len__(self) -> int:
        return len(self._data)
