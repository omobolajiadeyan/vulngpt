# Contributing

VulnGPT intentionally works without runtime dependencies in deterministic mode.

## Development

```bash
python -m unittest discover -s tests -v
python vulngpt.py CVE-2021-44228 --offline
```

## Analysis Changes

When changing triage or scoring behavior:

- Add or update tests in `tests/`.
- Prefer deterministic behavior for CI and demos.
- Keep offline fixtures small and synthetic or public-source derived.
- Document limitations clearly.

## Pull Requests

Good pull requests include a CVE fixture, expected analysis behavior, and a short
explanation of why the triage behavior changed.
