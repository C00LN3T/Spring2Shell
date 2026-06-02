"""Unit tests for checkpoint.py — scan resume support."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from spring2shell.core.checkpoint import Checkpoint


class TestCheckpoint:
    def test_new_checkpoint_empty(self, tmp_path):
        """A fresh checkpoint should have no scanned targets."""
        cp = Checkpoint(str(tmp_path / "scan"))
        assert not cp.is_resume
        assert cp.get_remaining(["http://a.com", "http://b.com"]) == ["http://a.com", "http://b.com"]

    def test_save_progress(self, tmp_path):
        """Saving progress should persist to disk."""
        cp = Checkpoint(str(tmp_path / "scan"))
        cp.save_progress("http://a.com", [{"url": "http://a.com", "status": "confirmed"}])

        checkpoint_file = tmp_path / "scan.checkpoint.json"
        assert checkpoint_file.exists()
        data = json.loads(checkpoint_file.read_text())
        assert "http://a.com" in data["scanned"]
        assert len(data["results"]) == 1

    def test_resume_skips_completed(self, tmp_path):
        """Resuming should skip already-scanned targets."""
        prefix = str(tmp_path / "scan")
        cp1 = Checkpoint(prefix)
        cp1.save_progress("http://a.com", [])
        cp1.save_progress("http://b.com", [])

        # Resume: only c.com should be remaining
        cp2 = Checkpoint(prefix)
        assert cp2.is_resume
        remaining = cp2.get_remaining(["http://a.com", "http://b.com", "http://c.com"])
        assert remaining == ["http://c.com"]

    def test_get_all_results_combines_sessions(self, tmp_path):
        """Results from both checkpoint and current session should be returned."""
        prefix = str(tmp_path / "scan")
        finding1 = {"url": "http://a.com", "status": "confirmed"}
        finding2 = {"url": "http://b.com", "status": "unverified"}

        cp1 = Checkpoint(prefix)
        cp1.save_progress("http://a.com", [finding1])

        cp2 = Checkpoint(prefix)
        cp2.save_progress("http://b.com", [finding2])

        results = cp2.get_all_results()
        assert len(results) == 2

    def test_finalize_removes_checkpoint_file(self, tmp_path):
        """finalize() should delete the checkpoint file."""
        prefix = str(tmp_path / "scan")
        cp = Checkpoint(prefix)
        cp.save_progress("http://a.com", [])

        checkpoint_file = tmp_path / "scan.checkpoint.json"
        assert checkpoint_file.exists()

        cp.finalize()
        assert not checkpoint_file.exists()

    def test_corrupt_checkpoint_handled_gracefully(self, tmp_path):
        """A corrupt checkpoint file should not crash on load."""
        prefix = str(tmp_path / "scan")
        checkpoint_file = tmp_path / "scan.checkpoint.json"
        checkpoint_file.write_text("NOT VALID JSON {{{{")

        # Should not raise
        cp = Checkpoint(prefix)
        assert not cp.is_resume
