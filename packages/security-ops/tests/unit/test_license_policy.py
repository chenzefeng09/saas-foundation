"""Tests for License allow/deny policy."""

from __future__ import annotations

from foundation_security_ops.services.license_policy import (
    evaluate_license,
    is_allowed,
    is_blocked,
)


class TestEvaluateLicense:
    def test_mit_allowed(self):
        assert evaluate_license("MIT") == "ALLOWED"

    def test_apache_allowed(self):
        assert evaluate_license("Apache-2.0") == "ALLOWED"

    def test_bsd_2_clause_allowed(self):
        assert evaluate_license("BSD-2-Clause") == "ALLOWED"

    def test_bsd_3_clause_allowed(self):
        assert evaluate_license("BSD-3-Clause") == "ALLOWED"

    def test_isc_allowed(self):
        assert evaluate_license("ISC") == "ALLOWED"

    def test_mpl_allowed(self):
        assert evaluate_license("MPL-2.0") == "ALLOWED"

    def test_gpl2_blocked(self):
        assert evaluate_license("GPL-2.0") == "BLOCKED"

    def test_gpl3_blocked(self):
        assert evaluate_license("GPL-3.0") == "BLOCKED"

    def test_agpl_blocked(self):
        assert evaluate_license("AGPL-3.0") == "BLOCKED"

    def test_agpl_only_blocked(self):
        assert evaluate_license("AGPL-3.0-only") == "BLOCKED"

    def test_lgpl_blocked(self):
        assert evaluate_license("LGPL-2.1") == "BLOCKED"

    def test_sspl_blocked(self):
        assert evaluate_license("SSPL-1.0") == "BLOCKED"

    def test_eupl_blocked(self):
        assert evaluate_license("EUPL-1.2") == "BLOCKED"

    def test_unknown_review_required(self):
        assert evaluate_license("LicenseRef-custom-proprietary") == "REVIEW_REQUIRED"

    def test_proprietary_review_required(self):
        assert evaluate_license("Proprietary") == "REVIEW_REQUIRED"

    def test_blocked_with_exception_allowed(self):
        # When exception_id is provided, blocked license becomes ALLOWED
        result = evaluate_license("GPL-2.0", exception_id="EX-2026-001")
        assert result == "ALLOWED"

    def test_allowed_with_exception_still_allowed(self):
        assert evaluate_license("MIT", exception_id="anything") == "ALLOWED"

    def test_whitespace_stripped(self):
        assert evaluate_license("  MIT  ") == "ALLOWED"
        assert evaluate_license("  GPL-3.0  ") == "BLOCKED"


class TestIsBlocked:
    def test_gpl_is_blocked(self):
        assert is_blocked("GPL-3.0") is True

    def test_mit_not_blocked(self):
        assert is_blocked("MIT") is False


class TestIsAllowed:
    def test_mit_allowed(self):
        assert is_allowed("MIT") is True

    def test_gpl_not_allowed(self):
        assert is_allowed("GPL-3.0") is False

    def test_unknown_not_allowed(self):
        assert is_allowed("Proprietary") is False
