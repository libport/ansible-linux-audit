#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the published DFSA JSON Schemas."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from test_catalog import VALIDATOR as CATALOG_VALIDATOR
from test_report import VALIDATOR as REPORT_VALIDATOR
from test_report import valid_report


ROOT = Path(__file__).resolve().parents[1]


class SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report_schema = json.loads(
            (ROOT / "schema/report.schema.json").read_text(encoding="utf-8")
        )
        cls.external_schema = json.loads(
            (ROOT / "schema/external-catalog.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(cls.report_schema)
        Draft202012Validator.check_schema(cls.external_schema)

    def test_report_schema_accepts_generated_shape(self) -> None:
        Draft202012Validator(
            self.report_schema,
            format_checker=FormatChecker(),
        ).validate(valid_report())

    def test_external_schema_accepts_valid_catalog(self) -> None:
        catalog = {
            "controls": [
                {
                    "id": "ORG-MANUAL-001",
                    "title": "Application owner is recorded",
                    "section": "governance",
                    "profiles": ["standard_server"],
                    "assessment": "manual",
                    "scored": False,
                    "handler": "manual",
                    "rationale": "Ownership requires organizational context.",
                    "references": ["https://example.invalid/policy"],
                    "manual_guidance": "Confirm a current owner is recorded.",
                }
            ],
            "task_files": [],
        }
        Draft202012Validator(
            self.external_schema,
            format_checker=FormatChecker(),
        ).validate(catalog)

    def test_external_schema_rejects_relative_task_path(self) -> None:
        catalog = {
            "controls": [],
            "task_files": ["relative-task.yml"],
        }
        errors = list(
            Draft202012Validator(self.external_schema).iter_errors(catalog)
        )
        self.assertTrue(errors)

    def test_profile_enums_are_consistent(self) -> None:
        report_profiles = set(
            self.report_schema["properties"]["audit"]["properties"]["profile"][
                "enum"
            ]
        )
        external_profiles = set(
            self.external_schema["$defs"]["control"]["properties"]["profiles"][
                "items"
            ]["enum"]
        )
        self.assertEqual(report_profiles, REPORT_VALIDATOR.PROFILES)
        self.assertEqual(external_profiles, REPORT_VALIDATOR.PROFILES)
        self.assertEqual(CATALOG_VALIDATOR.PROFILES, REPORT_VALIDATOR.PROFILES)

    def test_status_enums_are_consistent(self) -> None:
        schema_statuses = set(
            self.report_schema["$defs"]["result"]["properties"]["status"][
                "enum"
            ]
        )
        self.assertEqual(schema_statuses, REPORT_VALIDATOR.STATUSES)
        self.assertEqual(CATALOG_VALIDATOR.STATUSES, REPORT_VALIDATOR.STATUSES)


if __name__ == "__main__":
    unittest.main()
