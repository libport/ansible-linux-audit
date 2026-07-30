# Debian Family Security Audit

<!-- SPDX-License-Identifier: MIT -->

Debian Family Security Audit (DFSA) is an independent, read-only Ansible
security audit for systemd-based Debian-family Linux hosts and virtual
machines. It evaluates an independently authored, project-maintained baseline
without installing packages, changing configuration, or starting services on
managed hosts.

DFSA does not remediate findings and is not a third-party benchmark assessment
or certification.

## Audit coverage

The built-in baseline evaluates:

- filesystem and mount protections;
- package maintenance and repository trust;
- kernel hardening settings;
- host networking and firewall posture;
- local accounts, authentication, and OpenSSH;
- time synchronization, logging, and auditing;
- unnecessary network-facing services; and
- governance controls that require manual review.

Each control has an original `DFSA-*` identifier, rationale, technical
references, profile assignments, and either an automated implementation or
manual-review guidance.

## Requirements

### Controller

- Ansible Core 2.16, 2.17, 2.18, or 2.19
- Python supported by the selected Ansible Core release
- network and authentication access to each managed host

### Managed hosts

- Python 3
- a systemd-based operating system reported by Ansible as
  `os_family: Debian`
- privilege escalation sufficient to inspect protected system state

Containers, chroots, non-systemd systems, and non-Debian operating-system
families are rejected. Remediation is intentionally out of scope.

## Installation

From a repository checkout, create an isolated controller environment and
install a supported Ansible Core release:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "ansible-core>=2.16,<2.20"
```

The role declares no Ansible collection dependencies and does not install
packages on managed hosts.

## Quick start

Copy the example inventory and replace its documentation address and user with
the connection details for the target host:

```bash
cp inventory.example.yml inventory.yml
```

Store passwords in Ansible Vault or another secret source rather than in the
inventory. Then run the audit:

```bash
ansible-playbook -i inventory.yml audit.yml
```

The default `standard_server` profile reports noncompliance without failing the
play. The role writes the JSON report to
`artifacts/<inventory-host>-<UTC-timestamp>.json` on the controller.

To select the strict server profile and fail the play after writing the report
when a scored automated control fails or errors:

```bash
ansible-playbook -i inventory.yml audit.yml \
  -e dfsa_profile=strict_server \
  -e dfsa_fail_on_noncompliance=true
```

## Profiles

| Profile | Intended use |
| --- | --- |
| `standard_server` | General-purpose server baseline |
| `strict_server` | Standard server controls plus additional controls for sensitive or exposed servers |
| `standard_workstation` | Interactive workstation baseline |
| `strict_workstation` | Standard workstation controls plus additional controls for sensitive workstations |

Each strict profile contains every control in its corresponding standard
profile.

## Configuration

Set role variables in inventory, host or group variables, or with Ansible's
`-e` option.

### Selection and reporting

| Variable | Default | Accepted value | Effect |
| --- | --- | --- | --- |
| `dfsa_profile` | `standard_server` | `standard_server`, `strict_server`, `standard_workstation`, or `strict_workstation` | Selects the base control profile. |
| `dfsa_include_controls` | `[]` | Unique list of control IDs | Limits the audit to the listed controls. Every ID must exist and belong to the selected profile. An empty list includes every profile control. |
| `dfsa_exclude_controls` | `[]` | Unique list of control IDs | Removes listed controls from the result set. IDs must exist and must not also appear in `dfsa_include_controls`. |
| `dfsa_sections` | `[]` | Unique list of section names | Limits the audit to listed sections. Built-in sections are `filesystem`, `packages`, `kernel`, `network`, `identity`, `ssh`, `logging`, `services`, and `governance`. An empty list selects every section. |
| `dfsa_report_dir` | `{{ playbook_dir }}/artifacts` | Non-empty controller path | Selects the directory for JSON reports. |
| `dfsa_fail_on_noncompliance` | `false` | Boolean | Fails the play after writing the report when a scored automated result is `fail` or `error`. |
| `dfsa_run_heavy_checks` | `true` | Boolean | Runs filesystem-wide checks for world-writable directories and ownerless files. When false, selected heavy controls return `skipped`. |

Control selection applies the profile first, followed by the include list,
section filter, and exclusion list. Filters are recorded in report metadata.
Controls removed by a filter do not appear in the result set.

### Host classification and exceptions

| Variable | Default | Accepted value | Effect |
| --- | --- | --- | --- |
| `dfsa_host_network_role` | `endpoint` | `endpoint` or `router` | Determines whether packet forwarding is evaluated. The endpoint-forwarding control returns `not_applicable` for an explicitly declared router. |
| `dfsa_server_service_exceptions` | `[]` | Unique list containing `avahi-daemon` and/or `cups` | Marks the corresponding server service control `not_applicable` instead of testing the service state. |

Declare exceptions only when they are approved for the host's intended role;
an exception is not a passing assessment.

### Authentication thresholds

| Variable | Default | Accepted value | Effect |
| --- | --- | --- | --- |
| `dfsa_password_max_days` | `365` | Integer from 1 to 2147483647 | Maximum accepted `PASS_MAX_DAYS` value for new accounts. |
| `dfsa_password_min_days` | `1` | Integer from 0 to `dfsa_password_max_days` | Minimum accepted `PASS_MIN_DAYS` value for new accounts. |
| `dfsa_password_warning_days` | `14` | Integer from 0 to `dfsa_password_max_days` | Minimum accepted `PASS_WARN_AGE` value for new accounts. |
| `dfsa_inactive_password_days` | `30` | Integer from 0 to 2147483647 | Maximum accepted non-negative `useradd` inactive-password period. |
| `dfsa_password_min_length` | `14` | Integer from 1 to 2147483647 | Minimum password length accepted from a supported PAM password-quality configuration. |
| `dfsa_sshd_max_auth_tries` | `4` | Integer from 1 to 2147483647 | Maximum accepted effective OpenSSH `MaxAuthTries` value. |

### Private policy extensions

| Variable | Default | Accepted value | Effect |
| --- | --- | --- | --- |
| `dfsa_external_catalog_path` | `""` | Empty string or absolute controller path | Loads an additional YAML control catalog. |

For example:

```bash
ansible-playbook -i inventory.yml audit.yml \
  -e dfsa_external_catalog_path=/absolute/path/policy.yml
```

External catalogs may add manual controls and identify absolute local Ansible
task files for automated controls. Catalogs and task files are trusted
controller input, and task files execute with the role's privileges. Review
them as executable code before use; DFSA cannot enforce their read-only
behavior.

See the [external catalog schema](schema/external-catalog.schema.json) and
[control-authoring guide](docs/control-authoring.md) for the required format and
task contract.

## Reports and enforcement

Each report conforms to the [report schema](schema/report.schema.json) and
contains:

- the report schema and baseline versions;
- the selected profile, filters, and declared network role;
- host, distribution, kernel, architecture, and virtualization facts;
- UTC start and finish timestamps;
- totals for every result status; and
- one record per selected control, including bounded evidence and technical
  references.

Automated and manual controls use the following statuses:

| Status | Meaning |
| --- | --- |
| `pass` | Observed state satisfies the control. |
| `fail` | Observed state contradicts the control. |
| `error` | The probe could not reach a reliable decision. Missing tools and unreadable state are not treated as passes. |
| `manual_review` | Human or organizational judgment is required. |
| `not_applicable` | The control does not apply to the declared host role or an approved exception. |
| `skipped` | An operator disabled an optional expensive probe. |

By default, findings do not fail the play. When
`dfsa_fail_on_noncompliance` is true, DFSA writes the report first and then
fails if any scored automated control has `fail` or `error` status.
`manual_review`, `not_applicable`, and `skipped` do not trigger the gate.

The controller creates the report directory with mode `0750` and writes report
files with mode `0640`. Reports can reveal sensitive host configuration; store
them in an access-controlled location and apply an appropriate retention
policy.

## Read-only behavior

Built-in probes inspect current state without installing packages, starting
services, editing configuration, or intentionally persisting files on managed
hosts. Ansible may use and remove its normal ephemeral transport files;
pipelining is enabled in this repository.

The role intentionally creates or updates the report directory and writes JSON
reports on the controller. Running with `--check` does not suppress the audit:
built-in probes still execute and a controller-side report is still written.

These guarantees apply only to built-in DFSA tasks, not to operator-supplied
external task files.

## Development

Create a virtual environment and install all validation dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Run the repository's manual validation suite:

```bash
python tools/validate_catalog.py
python -m unittest discover -s tests -v
yamllint .
ansible-lint
ansible-playbook --syntax-check -i inventory.example.yml audit.yml
```

Validate generated reports independently when report files are present:

```bash
python tools/validate_report.py artifacts/*.json
```

This repository intentionally has no CI/CD workflow configuration. Before a
public release, follow the [release checklist](docs/release-checklist.md).

## License

Original repository content is licensed under the [MIT License](LICENSE). See
the [licensing policy](docs/licensing.md) for dependency, extension, and
third-party benchmark boundaries.
