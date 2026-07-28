#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the independently authored control catalog."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_catalog", ROOT / "tools/validate_catalog.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class CatalogTests(unittest.TestCase):
    @staticmethod
    def controls() -> list[dict]:
        data = VALIDATOR.yaml.safe_load(
            VALIDATOR.CATALOG_PATH.read_text(encoding="utf-8")
        )
        return data["dfsa_builtin_catalog"]

    def test_catalog_is_valid(self) -> None:
        automated, manual = VALIDATOR.validate()
        self.assertGreaterEqual(automated, 30)
        self.assertGreaterEqual(manual, 8)

    def test_baseline_has_no_third_party_control_namespace(self) -> None:
        text = VALIDATOR.CATALOG_PATH.read_text(encoding="utf-8")
        self.assertNotIn("CIS-", text)
        self.assertNotIn("Level 1", text)
        self.assertNotIn("Level 2", text)

    def test_strict_profiles_include_standard_profiles(self) -> None:
        controls = self.controls()
        for standard, strict in (
            ("standard_server", "strict_server"),
            ("standard_workstation", "strict_workstation"),
        ):
            standard_ids = {
                item["id"] for item in controls if standard in item["profiles"]
            }
            strict_ids = {
                item["id"] for item in controls if strict in item["profiles"]
            }
            self.assertLessEqual(standard_ids, strict_ids)


if __name__ == "__main__":
    unittest.main()
