# Control authoring

<!-- SPDX-License-Identifier: MIT -->

DFSA controls are catalog metadata paired with trusted Ansible check tasks.
Keeping metadata separate from executable checks makes profile selection,
reporting, review, and provenance predictable.

## Built-in control contract

Each catalog item contains:

```yaml
- id: DFSA-EXAMPLE-001
  title: An original, testable statement
  section: example
  profiles:
    - standard_server
    - strict_server
  assessment: automated
  scored: true
  handler: example_001
  rationale: An original explanation of the security outcome.
  references:
    - https://primary.example.invalid/authoritative-documentation
```

Manual controls set `assessment: manual`, `scored: false`, `handler: manual`,
and add `manual_guidance`. A control must belong to at least one profile.

Built-in automated controls require a task implementation under
`tasks/checks/`. A probe must:

1. inspect only current state;
2. set `changed_when: false`, `failed_when: false`, and `check_mode: false`;
3. avoid printing secrets or unbounded data; and
4. include `tasks/record_result.yml` exactly once when its control is selected.

Use these result meanings:

- `pass`: observed state meets the control;
- `fail`: observed state contradicts the control;
- `error`: the probe could not make a reliable decision;
- `not_applicable`: the control genuinely does not apply to the declared role;
- `skipped`: an operator disabled an optional expensive probe; or
- `manual_review`: human or organizational judgment is required.

Do not treat missing tools or unreadable state as a pass.

## External catalogs

An external catalog is a YAML mapping conforming to
[`schema/external-catalog.schema.json`](../schema/external-catalog.schema.json):

```yaml
---
controls:
  - id: ORG-MANUAL-001
    title: Application owner is recorded
    section: governance
    profiles: [standard_server, strict_server]
    assessment: manual
    scored: false
    handler: manual
    rationale: Ownership is organizational information.
    references:
      - https://policy.example.org/host-ownership
    manual_guidance: Confirm the asset record names a current accountable owner.
task_files: []
```

Automated external controls may list absolute local Ansible task files in
`task_files`. Those files run with the role's privilege and are trusted code.
They should call the result helper like this:

```yaml
- name: Run an organization-specific read-only probe
  ansible.builtin.command:
    argv: [/usr/bin/example, --inspect]
  register: org_probe
  changed_when: false
  failed_when: false
  check_mode: false
  when: "'ORG-EXAMPLE-001' in dfsa_selected_ids"

- name: Record the organization-specific result
  ansible.builtin.include_tasks: >-
    {{ role_path }}/tasks/record_result.yml
  vars:
    dfsa_record_control_id: ORG-EXAMPLE-001
    dfsa_record_status: "{{ 'pass' if org_probe.rc == 0 else 'fail' }}"
    dfsa_record_reason: Organization-specific explanation.
    dfsa_record_evidence: "{{ org_probe.stdout }}"
  when: "'ORG-EXAMPLE-001' in dfsa_selected_ids"
```

DFSA cannot enforce read-only behavior inside external task files. Review them
as executable code and do not point the role at untrusted input.

## Provenance requirements

Every new or revised control must identify primary technical references and
use original wording, selection, organization, and implementation. Do not
copy, translate, closely paraphrase, or reconstruct a restricted checklist.
Common technical facts can be implemented independently, but a third party's
expressive text, numbering, profile arrangement, or curated catalog must not
be imported without compatible permission.
