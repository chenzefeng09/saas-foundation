"""Unit tests for foundation_storage.config."""

from __future__ import annotations

import pytest

from foundation_storage.config import StorageSettings, get_settings


class TestStorageSettings:
    def test_defaults(self) -> None:
        s = StorageSettings()
        assert s.endpoint == "http://127.0.0.1:9001"
        assert s.region == "cn-default"
        assert s.access_key == "foundation"
        assert s.bucket_audit == "foundation-audit"
        assert s.bucket_workspace == "foundation-workspace"
        assert s.bucket_kb_raw == "foundation-kb-raw"
        assert s.bucket_kb_derived == "foundation-kb-derived"
        assert s.presigned_url_ttl_seconds == 3600
        assert s.multipart_threshold_bytes == 52428800
        assert s.access_control_enabled is True
        assert s.dlp_url.endswith("/api/dlp/v1")
        assert s.quota_check_enabled is True
        assert s.quota_db_dsn is None

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STORAGE_ENDPOINT", "https://s3.example.com")
        monkeypatch.setenv("STORAGE_BUCKET_AUDIT", "custom-audit")
        monkeypatch.setenv("STORAGE_QUOTA_CHECK_ENABLED", "false")
        s = StorageSettings()
        assert s.endpoint == "https://s3.example.com"
        assert s.bucket_audit == "custom-audit"
        assert s.quota_check_enabled is False

    def test_get_settings_cached(self) -> None:
        a = get_settings()
        b = get_settings()
        assert a is b
