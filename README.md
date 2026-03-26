# abom-advisories

Community-curated advisory database for [abom](https://github.com/JulietSecurity/abom) — the Actions Bill of Materials tool.

## How it works

`abom --check` fetches `db/advisories.json` from this repo at runtime to flag known-compromised GitHub Actions in your CI/CD pipelines.

The database is fetched automatically — no configuration needed. If the fetch fails (offline, rate limited), abom falls back to built-in data shipped with each release.

## Current advisories

| ID | CVE | Description |
|----|-----|-------------|
| ABOM-2026-001 | CVE-2026-33634 | Trivy GitHub Actions supply chain compromise |

## Contributing

Anyone can submit a PR to add a new advisory. Your PR must:

- Follow the schema in `db/advisories.json`
- Include at least one reference to a public advisory or CVE
- Clearly describe what was compromised and when

Maintainers review and merge. No auto-merge — we're the editorial layer ensuring data quality.

## Advisory format

See the [abom documentation](https://github.com/JulietSecurity/abom) for the full schema specification.

## License

[Apache 2.0](LICENSE)

---

Maintained by [Juliet Security](https://juliet.sh) · [Contact](mailto:contact@juliet.sh)
