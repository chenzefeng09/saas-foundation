"""Unit tests for foundation_storage.keys."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

import pytest

from foundation_storage.errors import KeyValidationError
from foundation_storage.keys import BucketPurpose, ObjectKey


class TestObjectKeyValidation:
    def test_valid_tenant_and_segments(self) -> None:
        k = ObjectKey(BucketPurpose.WORKSPACE, "tnt_01", ("a", "b.txt"))
        assert k.key == "tenants/tnt_01/a/b.txt"

    @pytest.mark.parametrize(
        "tid",
        ["", "x" * 65, "with/slash", "with space", "with$char"],
    )
    def test_invalid_tenant_id(self, tid: str) -> None:
        with pytest.raises(KeyValidationError):
            ObjectKey(BucketPurpose.WORKSPACE, tid, ("a",))

    def test_empty_segments_rejected(self) -> None:
        with pytest.raises(KeyValidationError):
            ObjectKey(BucketPurpose.WORKSPACE, "tnt_01", ())

    @pytest.mark.parametrize("bad", ["", ".", "..", "a/b"])
    def test_bad_segment_rejected(self, bad: str) -> None:
        with pytest.raises(KeyValidationError):
            ObjectKey(BucketPurpose.WORKSPACE, "tnt_01", ("ok", bad))


class TestFactories:
    def test_for_audit_event(self) -> None:
        ts = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        k = ObjectKey.for_audit_event("tnt_01", ts, "evt_xyz")
        assert k.purpose == BucketPurpose.AUDIT
        assert k.key == "tenants/tnt_01/year=2026/month=01/day=02/hour=03/evt_xyz.json"

    def test_for_workspace_file(self) -> None:
        k = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        assert k.purpose == BucketPurpose.WORKSPACE
        assert k.key == "tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf"

    def test_for_security_ops_report(self) -> None:
        k = ObjectKey.for_security_ops_report("tnt_01", "incident", "i_1", "r.json")
        assert k.purpose == BucketPurpose.WORKSPACE
        assert k.key == "tenants/tnt_01/security-ops/incident/i_1/r.json"

    def test_for_kb_raw_doc(self) -> None:
        k = ObjectKey.for_kb_raw_doc("tnt_01", "kb_1", "doc_1", "a.md")
        assert k.purpose == BucketPurpose.KB_RAW
        assert k.key == "tenants/tnt_01/kbs/kb_1/docs/doc_1/a.md"

    def test_for_kb_chunk(self) -> None:
        k = ObjectKey.for_kb_chunk("tnt_01", "kb_1", "doc_1", "c_1")
        assert k.purpose == BucketPurpose.KB_DERIVED
        assert k.key == "tenants/tnt_01/kbs/kb_1/docs/doc_1/chunks/c_1.json"


class TestSerialization:
    _BUCKET_MAP: ClassVar[dict[str, BucketPurpose]] = {
        "foundation-audit": BucketPurpose.AUDIT,
        "foundation-workspace": BucketPurpose.WORKSPACE,
        "foundation-kb-raw": BucketPurpose.KB_RAW,
        "foundation-kb-derived": BucketPurpose.KB_DERIVED,
    }

    def test_roundtrip_workspace(self) -> None:
        k = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        s = k.to_serialized("foundation-workspace")
        assert s == "foundation-workspace::tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf"
        back = ObjectKey.from_string(s, self._BUCKET_MAP)
        assert back == k

    def test_roundtrip_kb_derived(self) -> None:
        k = ObjectKey.for_kb_chunk("tnt_01", "kb_1", "doc_1", "c_1")
        s = k.to_serialized("foundation-kb-derived")
        back = ObjectKey.from_string(s, self._BUCKET_MAP)
        assert back.purpose == BucketPurpose.KB_DERIVED
        assert back == k

    def test_roundtrip_audit(self) -> None:
        ts = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        k = ObjectKey.for_audit_event("tnt_01", ts, "evt_x")
        s = k.to_serialized("foundation-audit")
        back = ObjectKey.from_string(s, self._BUCKET_MAP)
        assert back == k

    def test_roundtrip_staging_bucket_name(self) -> None:
        """Staging-style bucket name works when explicitly registered in the map."""
        staging_map = {
            "foundation-audit-staging": BucketPurpose.AUDIT,
        }
        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=UTC)
        k = ObjectKey.for_audit_event("tnt_01", ts, "evt_staging")
        s = k.to_serialized("foundation-audit-staging")
        back = ObjectKey.from_string(s, staging_map)
        assert back == k
        assert back.purpose == BucketPurpose.AUDIT

    def test_roundtrip_custom_bucket_name(self) -> None:
        """Fully custom (customer) bucket names work when in the explicit map."""
        custom_map = {"acme-corp-audit-logs": BucketPurpose.AUDIT}
        ts = datetime(2026, 5, 1, 8, 0, 0, tzinfo=UTC)
        k = ObjectKey.for_audit_event("tnt_acme", ts, "evt_1")
        s = k.to_serialized("acme-corp-audit-logs")
        back = ObjectKey.from_string(s, custom_map)
        assert back == k

    def test_from_string_missing_sep(self) -> None:
        with pytest.raises(KeyValidationError):
            ObjectKey.from_string("nosep", self._BUCKET_MAP)

    def test_from_string_empty_parts(self) -> None:
        with pytest.raises(KeyValidationError):
            ObjectKey.from_string("::tenants/x/a", self._BUCKET_MAP)
        with pytest.raises(KeyValidationError):
            ObjectKey.from_string("foundation-audit::", self._BUCKET_MAP)

    def test_from_string_unknown_bucket(self) -> None:
        with pytest.raises(KeyValidationError, match="unknown bucket"):
            ObjectKey.from_string("random-bucket::tenants/tnt_01/a", self._BUCKET_MAP)

    def test_from_string_missing_tenants_prefix(self) -> None:
        with pytest.raises(KeyValidationError):
            ObjectKey.from_string(
                "foundation-audit::other/tnt_01/a", self._BUCKET_MAP
            )
