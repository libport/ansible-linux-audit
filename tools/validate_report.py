#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate DFSA report structure and invariants using the standard library."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


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
MAX_EVIDENCE_LENGTH = 4096
TOP_LEVEL_FIELDS = {
    "schema_version",
    "baseline",
    "independent_project_notice",
    "host",
    "audit",
    "totals",
    "results",
}
BASELINE_FIELDS = {"id", "title", "version", "license"}
HOST_FIELDS = {
    "inventory_name",
    "hostname",
    "distribution",
    "distribution_version",
    "architecture",
    "kernel",
    "virtualization_role",
    "virtualization_type",
}
AUDIT_FIELDS = {
    "profile",
    "started_at",
    "finished_at",
    "include_controls",
    "exclude_controls",
    "sections",
    "network_role",
}
TOTAL_FIELDS = {"selected", *STATUSES}
RESULT_FIELDS = {
    "id",
    "title",
    "section",
    "assessment",
    "scored",
    "status",
    "reason",
    "evidence",
    "references",
}
TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)


def fail(message: str) -> None:
    raise ValueError(message)


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} has unexpected or missing fields: {sorted(set(value) ^ expected)}")


def nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    return value


def string_list(
    value: Any,
    label: str,
    *,
    allow_empty: bool = True,
) -> list[str]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    if not allow_empty and not value:
        fail(f"{label} must not be empty")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        fail(f"{label} must contain non-empty strings")
    if len(value) != len(set(value)):
        fail(f"{label} must not contain duplicates")
    return value


def nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label} must be a non-negative integer")
    return value


def timestamp(value: Any, label: str) -> datetime:
    text = nonempty_string(value, label)
    if not TIMESTAMP_PATTERN.fullmatch(text):
        fail(f"{label} must be a UTC RFC 3339 timestamp")
    try:
        return datetime.fromisoformat(f"{text[:-1]}+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid timestamp") from exc


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def validate(path: Path) -> None:
    report = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
    )
    report = mapping(report, "report")
    exact_fields(report, TOP_LEVEL_FIELDS, "report")

    if report["schema_version"] != "1.0":
        fail("unsupported schema_version")

    baseline = mapping(report["baseline"], "baseline")
    exact_fields(baseline, BASELINE_FIELDS, "baseline")
    for field in ("id", "title", "version"):
        nonempty_string(baseline[field], f"baseline.{field}")
    if baseline["license"] != "MIT":
        fail("baseline.license must be MIT")

    nonempty_string(
        report["independent_project_notice"],
        "independent_project_notice",
    )

    host = mapping(report["host"], "host")
    exact_fields(host, HOST_FIELDS, "host")
    for field in HOST_FIELDS:
        nonempty_string(host[field], f"host.{field}")

    audit = mapping(report["audit"], "audit")
    exact_fields(audit, AUDIT_FIELDS, "audit")
    if audit["profile"] not in PROFILES:
        fail("audit.profile is unknown")
    started_at = timestamp(audit["started_at"], "audit.started_at")
    finished_at = timestamp(audit["finished_at"], "audit.finished_at")
    if finished_at < started_at:
        fail("audit.finished_at precedes audit.started_at")
    include_controls = string_list(
        audit["include_controls"],
        "audit.include_controls",
    )
    exclude_controls = string_list(
        audit["exclude_controls"],
        "audit.exclude_controls",
    )
    string_list(audit["sections"], "audit.sections")
    if set(include_controls) & set(exclude_controls):
        fail("audit include and exclude filters overlap")
    if audit["network_role"] not in {"endpoint", "router"}:
        fail("audit.network_role is unknown")

    totals = mapping(report["totals"], "totals")
    exact_fields(totals, TOTAL_FIELDS, "totals")
    for field in TOTAL_FIELDS:
        nonnegative_integer(totals[field], f"totals.{field}")

    results = report["results"]
    if not isinstance(results, list):
        fail("results must be an array")

    ids: list[str] = []
    statuses: list[str] = []
    for index, raw_result in enumerate(results):
        label = f"results[{index}]"
        result = mapping(raw_result, label)
        exact_fields(result, RESULT_FIELDS, label)
        for field in ("id", "title", "section"):
            nonempty_string(result[field], f"{label}.{field}")
        ids.append(result["id"])

        if result["assessment"] not in {"automated", "manual"}:
            fail(f"{label}.assessment is unknown")
        if not isinstance(result["scored"], bool):
            fail(f"{label}.scored must be a Boolean")
        if result["assessment"] == "manual" and result["scored"]:
            fail(f"{label} manual result cannot be scored")

        status = result["status"]
        if status not in STATUSES:
            fail(f"{label}.status is unknown")
        statuses.append(status)
        if result["assessment"] == "manual" and status != "manual_review":
            fail(f"{label} manual result must have manual_review status")
        if status == "manual_review" and result["assessment"] != "manual":
            fail(f"{label} automated result cannot have manual_review status")

        if not isinstance(result["reason"], str):
            fail(f"{label}.reason must be a string")
        if not isinstance(result["evidence"], str):
            fail(f"{label}.evidence must be a string")
        if len(result["evidence"]) > MAX_EVIDENCE_LENGTH:
            fail(
                f"{label}.evidence exceeds "
                f"{MAX_EVIDENCE_LENGTH} characters"
            )

        references = string_list(
            result["references"],
            f"{label}.references",
            allow_empty=False,
        )
        for reference in references:
            parsed = urlparse(reference)
            if not parsed.scheme:
                fail(f"{label}.references contains a relative URI")

    if len(ids) != len(set(ids)):
        fail("result IDs must be unique")
    if ids != sorted(ids):
        fail("results must be sorted by ID")

    counts = Counter(statuses)
    if totals["selected"] != len(results):
        fail("totals.selected does not equal result count")
    for status in STATUSES:
        if totals[status] != counts[status]:
            fail(f"totals.{status} does not match result records")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        for report in args.reports:
            validate(report)
            print(f"report valid: {report}")
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"report validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
