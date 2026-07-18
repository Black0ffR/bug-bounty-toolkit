# Contributing to Bug Bounty Toolkit

Thanks for helping improve the toolkit. It is built for **authorized** security
research only — never point it at systems you do not have written permission to
test. See `README.md` for the responsible-use statement.

## Repository layout

```
scripts/        standalone tools (apifuzz, ssrfprobe, jsreaper, paramfuzz, ...)
toolkit/        shared libraries + composable "stages" wired by orchestrator.py
toolkit/tests/  pytest suite (run: python -m pytest toolkit/tests/ -q)
```

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .            # installs toolkit + entry points (if setup exists)
pip install -r requirements-dev.txt   # pytest, pyyaml, ...
```

## Workflow

1. Create a topic branch off `main`.
2. Make changes in small, focused commits (one concern per commit).
3. Add or update tests under `toolkit/tests/`.
4. **Tests must be green before committing:**
   ```bash
   python -m pytest toolkit/tests/ -q
   ```
5. Open a PR against `main` using the template (`.github/PULL_REQUEST_TEMPLATE.md`).

## Coding conventions

- Python 3.11+, `from __future__ import annotations` at the top of new files.
- No `print()` for diagnostics in libraries — use the `logging` module.
- New shared behaviour goes in `toolkit/infra/*`; tools stay thin CLI wrappers.
- Prefer pure functions for logic so they can be unit-tested without network.
- Keep secrets out of the repo (`.gitignore` already covers `*.pem`, `*.env`, ...).

## Tests

- Unit tests are preferred and must not require network access (mock HTTP).
- Each new feature/fix gets its own `test_<module>_<tag>.py` mirroring the issue.
- Use the existing fixtures in `toolkit/tests/` (mock `httpx.AsyncClient`, etc.).

## License

MIT — for authorized penetration testing and bug bounty research only.
