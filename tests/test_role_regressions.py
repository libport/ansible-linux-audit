#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for role logic that previously produced inaccurate reports."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "roles/debian_family_security_audit/tasks"


def task_named(path: Path, name: str) -> dict:
    tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
    return next(task for task in tasks if task.get("name") == name)


class InputAndTimestampTests(unittest.TestCase):
    def test_list_inputs_explicitly_reject_mappings(self) -> None:
        text = (TASKS / "initialize.yml").read_text(encoding="utf-8")
        for variable in (
            "dfsa_include_controls",
            "dfsa_exclude_controls",
            "dfsa_sections",
            "dfsa_server_service_exceptions",
            "dfsa_external_catalog_data.controls",
            "dfsa_external_catalog_data.task_files | default([])",
            "item.profiles",
            "item.references",
        ):
            with self.subTest(variable=variable):
                self.assertIn(f"{variable} is not mapping", text)

    def test_timestamps_are_eager_and_ordered(self) -> None:
        initialize = (TASKS / "initialize.yml").read_text(encoding="utf-8")
        report = (TASKS / "report.yml").read_text(encoding="utf-8")
        self.assertNotIn("{{ now(", initialize)
        self.assertNotIn("{{ now(", report)
        self.assertIn(
            'dfsa_started_at: "{{ dfsa_started_at_probe.stdout }}"', initialize
        )
        self.assertIn(
            'dfsa_finished_at: "{{ [dfsa_started_at, '
            'dfsa_finished_at_probe.stdout] | max }}"',
            report,
        )


class FirewallProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        task = task_named(
            TASKS / "checks/network.yml",
            "Inspect active host firewall rules",
        )
        shell = task["ansible.builtin.shell"]
        match = re.search(
            r"-c '\n(?P<code>.*?)\n[ \t]*'; then",
            shell,
            re.DOTALL,
        )
        if not match:
            raise AssertionError("Unable to extract nftables JSON evaluator")
        cls.evaluator = match.group("code")

    def evaluate(self, objects: list[dict] | object) -> int:
        document = {"nftables": objects}
        result = subprocess.run(
            [sys.executable, "-c", self.evaluator],
            input=json.dumps(document),
            text=True,
            capture_output=True,
            check=False,
        )
        return result.returncode

    @staticmethod
    def input_chain(policy: str = "accept") -> dict:
        return {
            "chain": {
                "family": "inet",
                "table": "filter",
                "name": "input",
                "type": "filter",
                "hook": "input",
                "prio": 0,
                "policy": policy,
            }
        }

    def test_empty_accept_chain_does_not_pass(self) -> None:
        self.assertEqual(self.evaluate([self.input_chain()]), 1)

    def test_drop_policy_passes(self) -> None:
        self.assertEqual(self.evaluate([self.input_chain("drop")]), 0)

    def test_direct_reject_rule_passes(self) -> None:
        objects = [
            self.input_chain(),
            {
                "rule": {
                    "family": "inet",
                    "table": "filter",
                    "chain": "input",
                    "expr": [
                        {"match": {"left": {"payload": "tcp"}, "right": 23}},
                        {"reject": {"type": "tcp reset"}},
                    ],
                }
            },
        ]
        self.assertEqual(self.evaluate(objects), 0)

    def test_reachable_jump_chain_passes(self) -> None:
        objects = [
            self.input_chain(),
            {
                "chain": {
                    "family": "inet",
                    "table": "filter",
                    "name": "deny-list",
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "filter",
                    "chain": "input",
                    "expr": [{"jump": {"target": "deny-list"}}],
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "filter",
                    "chain": "deny-list",
                    "expr": [{"drop": None}],
                }
            },
        ]
        self.assertEqual(self.evaluate(objects), 0)

    def test_disconnected_drop_chain_does_not_pass(self) -> None:
        objects = [
            self.input_chain(),
            {
                "chain": {
                    "family": "inet",
                    "table": "filter",
                    "name": "unused",
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "filter",
                    "chain": "unused",
                    "expr": [{"drop": None}],
                }
            },
        ]
        self.assertEqual(self.evaluate(objects), 1)

    def test_malformed_document_is_an_error(self) -> None:
        result = subprocess.run(
            [sys.executable, "-c", self.evaluator],
            input="[]",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)


class TimeSynchronizationProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        task = task_named(
            TASKS / "checks/logging.yml",
            "Inspect active time synchronization",
        )
        cls.probe = task["ansible.builtin.shell"]

    def run_probe(
        self, output: str, command_status: int = 0
    ) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as directory:
            stub = Path(directory) / "timedatectl"
            stub.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$DFSA_TIMEDATECTL_OUTPUT\"\n"
                'exit "$DFSA_TIMEDATECTL_STATUS"\n',
                encoding="utf-8",
            )
            stub.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{directory}:{environment['PATH']}",
                    "DFSA_TIMEDATECTL_OUTPUT": output,
                    "DFSA_TIMEDATECTL_STATUS": str(command_status),
                }
            )
            return subprocess.run(
                ["/bin/bash", "-c", self.probe],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )

    def test_synchronized_clock_passes(self) -> None:
        result = self.run_probe("yes")
        self.assertEqual(result.returncode, 0)

    def test_unsynchronized_clock_fails(self) -> None:
        result = self.run_probe("no")
        self.assertEqual(result.returncode, 1)

    def test_query_failure_is_an_error(self) -> None:
        result = self.run_probe("system bus unavailable", command_status=1)
        self.assertEqual(result.returncode, 2)

    def test_unexpected_value_is_an_error(self) -> None:
        result = self.run_probe("unknown")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
