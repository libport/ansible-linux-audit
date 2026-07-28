#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the standalone DFSA report validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_report", ROOT / "tools/validate_report.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def valid_report() -> dict:
    return {
        "schema_version": "1.0",
        "baseline": {
            "id": "DFSA",
            "title": "Debian Family Security Audit Baseline",
            "version": "1.0.0",
            "license": "MIT",
        },
        "independent_project_notice": "Independent baseline.",
        "host": {
            "inventory_name": "example",
            "hostname": "example",
            "distribution": "Debian",
            "distribution_version": "13",
            "architecture": "x86_64",
            "kernel": "6.12.0",
            "virtualization_role": "guest",
            "virtualization_type": "kvm",
        },
        "audit": {
            "profile": "standard_server",
            "started_at": "2026-07-29T00:00:00.000000Z",
            "finished_at": "2026-07-29T00:00:01.000000Z",
            "include_controls": [],
            "exclude_controls": [],
            "sections": [],
            "network_role": "endpoint",
        },
        "totals": {
            "selected": 1,
            "pass": 1,
            "fail": 0,
            "error": 0,
            "manual_review": 0,
            "not_applicable": 0,
            "skipped": 0,
        },
        "results": [
            {
                "id": "DFSA-KRN-001",
                "title": "Full address-space randomization is enabled",
                "section": "kernel",
                "assessment": "automated",
                "scored": True,
                "status": "pass",
                "reason": "Observed expected value.",
                "evidence": "2",
                "references": [
                    "https://docs.kernel.org/admin-guide/sysctl/kernel.html"
                ],
            }
        ],
    }


class ReportValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.report_path = Path(self.temporary_directory.name) / "report.json"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, report: object) -> None:
        self.report_path.write_text(json.dumps(report), encoding="utf-8")

    def test_valid_report_is_accepted(self) -> None:
        self.write(valid_report())
        VALIDATOR.validate(self.report_path)

    def test_invalid_nested_structure_is_rejected(self) -> None:
        cases = {
            "missing result title": lambda report: report["results"][0].pop("title"),
            "Boolean total": lambda report: report["totals"].__setitem__(
                "selected", True
            ),
            "non-object baseline": lambda report: report.__setitem__("baseline", []),
            "oversized evidence": lambda report: report["results"][0].__setitem__(
                "evidence", "x" * 4097
            ),
            "overlapping filters": lambda report: (
                report["audit"].__setitem__(
                    "include_controls", ["DFSA-KRN-001"]
                ),
                report["audit"].__setitem__(
                    "exclude_controls", ["DFSA-KRN-001"]
                ),
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                report = copy.deepcopy(valid_report())
                mutate(report)
                self.write(report)
                with self.assertRaises(ValueError):
                    VALIDATOR.validate(self.report_path)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        self.report_path.write_text(
            '{"schema_version":"1.0","schema_version":"1.0"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            VALIDATOR.validate(self.report_path)

    def test_schema_uses_the_validator_evidence_bound(self) -> None:
        schema = json.loads(
            (ROOT / "schema/report.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["$defs"]["result"]["properties"]["evidence"]["maxLength"],
            VALIDATOR.MAX_EVIDENCE_LENGTH,
        )


if __name__ == "__main__":
    unittest.main()
