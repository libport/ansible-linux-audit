#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the built-in DFSA catalog without nonstandard validator libraries."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "roles/debian_family_security_audit/vars/main.yml"
CHECKS_PATH = ROOT / "roles/debian_family_security_audit/tasks/checks"
PROFILES = {
    "standard_server",
    "strict_server",
    "standard_workstation",
    "strict_workstation",
}
STATUSES = {
    "pass",
    "fail",
    "error",
    "manual_review",
    "not_applicable",
    "skipped",
}
REQUIRED = {
    "id",
    "title",
    "section",
    "profiles",
    "assessment",
    "scored",
    "handler",
    "rationale",
    "references",
}
BASELINE_FIELDS = {"id", "title", "version", "license"}
ID_PATTERN = re.compile(r"^DFSA-[A-Z]+-[0-9]{3}$")
HANDLER_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
RECORDED_ID_PATTERN = re.compile(
    r"dfsa_record_control_id:\s*(DFSA-[A-Z]+-[0-9]{3})\b"
)


def fail(message: str) -> None:
    raise ValueError(message)


def validate() -> tuple[int, int]:
    data = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        fail("catalog file must contain a YAML mapping")
    runtime_profiles = data.get("dfsa_internal_valid_profiles")
    runtime_statuses = data.get("dfsa_internal_valid_statuses")
    if (
        not isinstance(runtime_profiles, list)
        or any(not isinstance(profile, str) for profile in runtime_profiles)
        or len(runtime_profiles) != len(set(runtime_profiles))
        or set(runtime_profiles) != PROFILES
    ):
        fail("runtime profile list does not match the validator")
    if (
        not isinstance(runtime_statuses, list)
        or any(not isinstance(status, str) for status in runtime_statuses)
        or len(runtime_statuses) != len(set(runtime_statuses))
        or set(runtime_statuses) != STATUSES
    ):
        fail("runtime status list does not match the validator")
    baseline = data.get("dfsa_baseline")
    controls = data.get("dfsa_builtin_catalog")
    if not isinstance(baseline, dict) or set(baseline) != BASELINE_FIELDS:
        fail("dfsa_baseline must contain id, title, version, and license")
    for field in ("id", "title", "version"):
        if not isinstance(baseline[field], str) or not baseline[field].strip():
            fail(f"dfsa_baseline {field} must be a non-empty string")
    if baseline["id"] != "DFSA" or baseline["license"] != "MIT":
        fail("dfsa_baseline must identify DFSA under the MIT license")
    if not isinstance(controls, list) or not controls:
        fail("dfsa_builtin_catalog must be a non-empty list")

    check_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(CHECKS_PATH.glob("*.yml"))
    )
    recorded_ids = set(RECORDED_ID_PATTERN.findall(check_text))
    seen_ids: set[str] = set()
    seen_handlers: set[str] = set()
    automated_ids: set[str] = set()
    manual_ids: set[str] = set()
    automated_count = 0
    manual_count = 0

    for index, control in enumerate(controls):
        if not isinstance(control, dict):
            fail(f"control at index {index} is not a mapping")
        missing = REQUIRED - control.keys()
        if missing:
            fail(f"{control.get('id', index)} missing fields: {sorted(missing)}")
        unexpected = control.keys() - (REQUIRED | {"manual_guidance"})
        if unexpected:
            fail(
                f"{control.get('id', index)} has unexpected fields: "
                f"{sorted(unexpected)}"
            )

        control_id = control["id"]
        if not isinstance(control_id, str) or not ID_PATTERN.fullmatch(control_id):
            fail(f"invalid built-in control ID: {control_id!r}")
        if control_id in seen_ids:
            fail(f"duplicate control ID: {control_id}")
        seen_ids.add(control_id)

        for field in ("title", "section", "handler", "rationale"):
            if not isinstance(control[field], str) or not control[field].strip():
                fail(f"{control_id} has an empty or non-string {field}")
        if not HANDLER_PATTERN.fullmatch(control["handler"]):
            fail(f"{control_id} has an invalid handler name")
        if not isinstance(control["profiles"], list) or not control["profiles"]:
            fail(f"{control_id} requires at least one profile")
        if any(not isinstance(profile, str) for profile in control["profiles"]):
            fail(f"{control_id} profiles must be strings")
        if len(control["profiles"]) != len(set(control["profiles"])):
            fail(f"{control_id} repeats a profile")
        unknown_profiles = set(control["profiles"]) - PROFILES
        if unknown_profiles:
            fail(f"{control_id} has unknown profiles: {sorted(unknown_profiles)}")
        if not isinstance(control["scored"], bool):
            fail(f"{control_id} scored must be a Boolean")
        if not isinstance(control["references"], list) or not control["references"]:
            fail(f"{control_id} requires at least one reference")
        if any(not isinstance(reference, str) for reference in control["references"]):
            fail(f"{control_id} references must be strings")
        if len(control["references"]) != len(set(control["references"])):
            fail(f"{control_id} repeats a reference")
        for reference in control["references"]:
            parsed = urlparse(reference)
            if parsed.scheme != "https" or not parsed.netloc:
                fail(f"{control_id} has a non-HTTPS reference: {reference!r}")

        assessment = control["assessment"]
        handler = control["handler"]
        if assessment == "manual":
            manual_count += 1
            manual_ids.add(control_id)
            if handler != "manual" or control["scored"]:
                fail(f"{control_id} manual controls must be unscored with handler=manual")
            if (
                not isinstance(control.get("manual_guidance"), str)
                or not control["manual_guidance"].strip()
            ):
                fail(f"{control_id} manual control lacks guidance")
        elif assessment == "automated":
            automated_count += 1
            automated_ids.add(control_id)
            if not control["scored"]:
                fail(f"{control_id} automated built-in controls must be scored")
            if "manual_guidance" in control:
                fail(f"{control_id} automated control cannot have manual guidance")
            expected_handler = "_".join(control_id.split("-")[1:]).lower()
            if handler != expected_handler:
                fail(
                    f"{control_id} handler must be {expected_handler}, "
                    f"not {handler}"
                )
            if handler in seen_handlers:
                fail(f"duplicate automated handler: {handler}")
            seen_handlers.add(handler)
        else:
            fail(f"{control_id} has invalid assessment: {assessment!r}")

    missing_implementations = automated_ids - recorded_ids
    if missing_implementations:
        fail(
            "automated controls without result tasks: "
            f"{sorted(missing_implementations)}"
        )
    unexpected_implementations = recorded_ids - automated_ids
    if unexpected_implementations:
        fail(
            "check tasks record unknown or non-automated controls: "
            f"{sorted(unexpected_implementations)}"
        )
    if manual_ids & recorded_ids:
        fail("manual controls must not have automated result tasks")

    for profile in PROFILES:
        if not any(profile in item["profiles"] for item in controls):
            fail(f"profile has no controls: {profile}")

    return automated_count, manual_count


def main() -> int:
    try:
        automated, manual = validate()
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        print(f"catalog validation failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"catalog valid: {automated + manual} controls "
        f"({automated} automated, {manual} manual)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
