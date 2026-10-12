"""Tests for fast-path SHA-256 cache and tamper-evident audit log."""

from pathlib import Path

from clarusav.store.audit import AuditLog
from clarusav.store.cache import FastPathCache


def test_fast_path_cache_lifecycle(tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"
    cache = FastPathCache(cache_file)

    test_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert cache.get(test_sha, model_version="0.1.0") is None

    cache.set(
        sha256=test_sha,
        model_version="0.1.0",
        verdict="BENIGN",
        score=0.05,
        band_position="BENIGN_BAND",
        deciding_stage="static_gate",
    )

    # Cache hit
    hit = cache.get(test_sha, model_version="0.1.0")
    assert hit is not None
    assert hit["verdict"] == "BENIGN"
    assert hit["score"] == 0.05

    # Cache miss on model version update (cache invalidation)
    miss = cache.get(test_sha, model_version="0.2.0")
    assert miss is None

    # Clear cache
    cache.clear()
    assert cache.get(test_sha, model_version="0.1.0") is None


def test_audit_log_hash_chain_verification(tmp_path: Path) -> None:
    audit_file = tmp_path / "audit.log"
    log = AuditLog(audit_file)

    # Empty log is valid
    valid, msg, count = log.verify()
    assert valid is True
    assert count == 0

    # Append entries
    entry1 = log.append(
        file_sha256="aaa111",
        target_path="/samples/file1.exe",
        verdict="BENIGN",
        score=0.10,
        deciding_stage="static_gate",
        model_version="0.1.0",
        tau_high=0.85,
        tau_low=0.15,
    )
    assert entry1.index == 0
    assert entry1.prev_hash == AuditLog.GENESIS_HASH

    entry2 = log.append(
        file_sha256="bbb222",
        target_path="/samples/file2.exe",
        verdict="MALICIOUS",
        score=0.95,
        deciding_stage="static_gate",
        model_version="0.1.0",
        tau_high=0.85,
        tau_low=0.15,
    )
    assert entry2.index == 1
    assert entry2.prev_hash == entry1.entry_hash

    # Verify intact chain
    valid, msg, count = log.verify()
    assert valid is True
    assert count == 2


def test_audit_log_detects_tampering(tmp_path: Path) -> None:
    audit_file = tmp_path / "audit.log"
    log = AuditLog(audit_file)

    log.append(
        file_sha256="aaa111",
        target_path="/samples/good.exe",
        verdict="BENIGN",
        score=0.10,
        deciding_stage="static_gate",
        model_version="0.1.0",
        tau_high=0.85,
        tau_low=0.15,
    )
    log.append(
        file_sha256="bbb222",
        target_path="/samples/bad.exe",
        verdict="MALICIOUS",
        score=0.95,
        deciding_stage="static_gate",
        model_version="0.1.0",
        tau_high=0.85,
        tau_low=0.15,
    )

    # Tamper with the log file: change verdict of second entry from MALICIOUS to BENIGN
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    tampered_line = lines[1].replace('"MALICIOUS"', '"BENIGN"')
    audit_file.write_text(lines[0] + "\n" + tampered_line + "\n", encoding="utf-8")

    # Verify must fail
    valid, msg, count = log.verify()
    assert valid is False
    assert "Tamper detected" in msg
