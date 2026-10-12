"""Tests for QuarantineManager vault isolation and restoration."""

import os
from pathlib import Path

import pytest

from clarusav.quarantine.manager import QuarantineManager


def test_quarantine_isolation_and_restore(tmp_path: Path) -> None:
    vault_dir = tmp_path / "vault"
    manager = QuarantineManager(vault_dir)

    # Create dummy target file
    sample_dir = tmp_path / "work"
    sample_dir.mkdir()
    sample_file = sample_dir / "malware.exe"
    sample_file.write_bytes(b"MZ\x90\x00synthetic_payload_test")

    # Quarantine file
    record = manager.quarantine(sample_file, reason="TEST_MALICIOUS")
    assert not sample_file.exists()  # Original file removed
    assert Path(record.quarantine_path).is_file()

    # Check permission stripping: file mode should be 0o600
    st = os.stat(record.quarantine_path)
    assert (st.st_mode & 0o777) == 0o600

    # List records
    records = manager.list_records()
    assert len(records) == 1
    assert records[0].item_id == record.item_id
    assert records[0].restored is False

    # Restore file
    restored = manager.restore(record.item_id)
    assert restored == sample_file
    assert sample_file.is_file()
    assert sample_file.read_bytes() == b"MZ\x90\x00synthetic_payload_test"

    # Restoring twice raises ValueError
    with pytest.raises(ValueError, match="already been restored"):
        manager.restore(record.item_id)
