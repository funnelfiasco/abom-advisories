# abom-advisories

Community-curated advisory database for [abom](https://github.com/JulietSecurity/abom) — the Actions Bill of Materials tool.

## How it works

`abom --check` fetches `db/advisories.json` from this repo at runtime to flag known-compromised GitHub Actions in your CI/CD pipelines.

The database is fetched automatically — no configuration needed. If the fetch fails (offline, rate limited), abom falls back to built-in data shipped with each release.

## Current advisories

See [julietsecurity.github.io/abom-advisories/db/advisories.json](https://julietsecurity.github.io/abom-advisories/db/advisories.json) for the current list.

## Contributing

Anyone can submit a PR to add a new advisory. Your PR must:

- Conform to the OSV schema plus ABOM extensions
- Use a unique `id` in the form `ABOM-YYYY-NNNN`
- Include at least one reference to a public advisory or CVE
- Clearly describe what was compromised and when

Maintainers review and merge. No auto-merge — we're the editorial layer ensuring data quality.

## Advisory format

Advisories use the [OSV schema](https://ossf.github.io/osv-schema/) (v1.7.5). ABOM-specific fields live in two extension namespaces:

- `ecosystem_specific.abom` for GitHub-Actions-specific signal (`tool_names` for wrapper detection, `affected_period` for incident time windows)
- `database_specific.abom` for ABOM-wide signal (`indicators` for IoC data, `recommended_actions` for remediation steps)

## License

[Apache 2.0](LICENSE)

---

Maintained by [Juliet Security](https://juliet.sh) · [Contact](mailto:contact@juliet.sh)
