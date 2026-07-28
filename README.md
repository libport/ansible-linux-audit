# Debian Family Security Audit

An independent, read-only Ansible audit for systemd-based Debian-family Linux
hosts and virtual machines. The project evaluates an original,
owner-maintained security baseline without installing packages or changing
managed hosts.

## What it audits

The built-in Debian Family Security Audit (DFSA) baseline covers:

- filesystem and mount protections;
- package maintenance and repository trust;
- kernel hardening settings;
- host networking and firewall posture;
- local accounts, authentication, and OpenSSH;
- time synchronization, logging, and auditing;
- unnecessary network-facing services; and
- manual governance checks that cannot be decided safely from host state.

Every control has an original `DFSA-*` identifier, implementation, rationale,
and provenance record. Results are `pass`, `fail`, `error`, `manual_review`,
`not_applicable`, or `skipped`.

## Requirements

- Ansible Core 2.16 through 2.19 on the controller
- Python 3 on each managed host
- privilege escalation sufficient to read protected configuration
- a systemd-based operating system reported by Ansible as `os_family: Debian`

Containers, chroots, non-systemd systems, and remediation are intentionally out
of scope for the initial release.

## Quick start

Copy the example inventory, replace the host, and run:

```bash
cp inventory.example.yml inventory.yml
ansible-playbook -i inventory.yml audit.yml
```

The default profile is `standard_server`. Reports are written to
`artifacts/<host>-<timestamp>.json` on the controller. Noncompliance is reported
without failing the play by default.

To audit a stricter server profile and make scored findings fail the play:

```bash
ansible-playbook -i inventory.yml audit.yml \
  -e dfsa_profile=strict_server \
  -e dfsa_fail_on_noncompliance=true
```

### Profiles

| Profile | Intended use |
| --- | --- |
| `standard_server` | Practical baseline for general-purpose servers |
| `strict_server` | Additional checks for sensitive or exposed servers |
| `standard_workstation` | Practical baseline for interactive systems |
| `strict_workstation` | Additional checks for sensitive workstations |

Strict profiles include all controls in their corresponding standard profile.

### Useful variables

```yaml
dfsa_profile: standard_server
dfsa_include_controls: []       # Empty means all controls in the profile.
dfsa_exclude_controls: []
dfsa_sections: []               # Example: [kernel, ssh]
dfsa_report_dir: "{{ playbook_dir }}/artifacts"
dfsa_fail_on_noncompliance: false
dfsa_run_heavy_checks: true
dfsa_host_network_role: endpoint  # Or router.
dfsa_server_service_exceptions: []  # Supported entries: avahi-daemon, cups.
```

Control filters are applied after profile selection. An included control must
belong to the selected profile. Excluded controls are omitted from results and
listed in report metadata.

## Read-only behavior

The role gathers facts and executes inspection commands with
`changed_when: false`. It does not install packages, start services, edit
configuration, or persist files on managed hosts. Ansible may use its normal
ephemeral transport files; pipelining is enabled and Ansible removes any
transport artifacts. JSON reports are the only intentional writes and occur on
the controller.

Run with `--check` if desired. Read-only probes still execute so that check mode
produces a real audit.

## Reports and enforcement

Each JSON report contains:

- baseline name and version;
- selected profile and filters;
- host, distribution, kernel, and architecture facts;
- start/end timestamps and result totals; and
- one record per selected control, with status, reason, and bounded evidence.

When `dfsa_fail_on_noncompliance` is true, the role writes the report first and
then fails if a scored automated control has `fail` or `error` status.
`manual_review`, `not_applicable`, and `skipped` do not fail the gate.

Audit output can reveal host configuration and should be treated as sensitive.
The default controller report mode is `0640`; store artifacts in an
access-controlled location and apply an appropriate retention policy.

## Private policy extensions

Organizations may load their own appropriately licensed policy catalog:

```bash
ansible-playbook -i inventory.yml audit.yml \
  -e dfsa_external_catalog_path=/absolute/path/policy.yml
```

External catalogs are trusted controller input. They can add manual controls
directly and can name local Ansible task files for automated checks. See
[Control authoring](docs/control-authoring.md). The project does not ship
third-party benchmark mappings, converters, or extraction tools.

## Development

Validation is run manually. This repository intentionally contains no CI/CD
workflow configuration.

```bash
python3 tools/validate_catalog.py
python3 -m unittest discover -s tests -v
yamllint .
ansible-lint
ansible-playbook --syntax-check -i inventory.example.yml audit.yml
```

Generated JSON can be checked independently:

```bash
python3 tools/validate_report.py artifacts/*.json
```

### Project maintenance

Repository maintenance is owner-only. External pull requests, patches, and
other repository contributions are not accepted. This upstream policy does not
limit the rights granted by the MIT License: recipients may use, modify, and
fork the software, but changes from independent forks will not be merged into
this repository.

The project does not accept security or vulnerability reports and does not
provide or monitor a reporting channel or security-response service. Do not
submit credentials, private keys, password hashes, or production audit output
through repository features. Users are responsible for evaluating the
software, tracking relevant dependencies, applying necessary mitigations, and
maintaining changes in their own forks.

Owner-authored changes must be original or clearly MIT-compatible and must not
reconstruct restricted third-party benchmarks.

Before publishing a promoted release, review the
[licensing boundaries](docs/licensing.md) and
[release checklist](docs/release-checklist.md).

## License

Original repository content is licensed under the [MIT License](LICENSE). MIT
is an open-source license, not a public-domain dedication: recipients may use,
modify, distribute, sublicense, and sell the work, but must retain its
copyright and license notice.
