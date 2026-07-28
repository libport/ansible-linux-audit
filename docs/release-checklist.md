# Public release checklist

<!-- SPDX-License-Identifier: MIT -->

- [ ] Confirm `libport` owns or is authorized to license all repository content.
- [ ] Run `python3 tools/validate_catalog.py`.
- [ ] Run unit, YAML, Ansible lint, and syntax checks.
- [ ] Confirm validation remains manual and no CI/CD workflow configuration is present.
- [ ] Audit the Git history for restricted third-party content.
- [ ] Confirm every built-in control has original wording, identifiers, and implementation.
- [ ] Confirm every distributed source file is MIT-compatible and provenance is recorded.
- [ ] Confirm no report or document claims third-party benchmark compliance or certification.
- [ ] Confirm no third-party logos, badges, or confusing visual branding are present.
- [ ] Confirm the repository name and project branding remain neutral and independently authored.
- [ ] Tag the release only after all applicable checks above are resolved.
