# QUICKSTART — Bug Bounty Toolkit

End-to-end guide: from `scope.yaml` to `triage_queue.md` in 5 commands.

## Prerequisites

```bash
# Python 3.9+
python3 --version

# Required Python packages
pip install httpx pyyaml

# Optional but recommended
pip install beautifulsoup4 rich  # improves jsreaper / nuclei-harvest output
```

The toolkit runs on Termux (Android) — see `scripts/termux_recon_setup.sh` for
the Android-specific install path.

## 1. Configure scope + auth

Copy the example configs and edit:

```bash
cd SubTakeover/
cp toolkit/configs/scope.example.yaml scope.yaml
cp toolkit/configs/auth_profiles.example.yaml auth_profiles.yaml
$EDITOR scope.yaml auth_profiles.yaml
```

`scope.yaml` defines what's in/out of scope and the rate limit. Every tool in
the pipeline calls `scope_guard.check_scope()` before firing any request — out-
of-scope targets raise immediately. `auth_profiles.yaml` defines your test
identities; `idor_crosssession.py` needs at least two non-anon profiles to
verify BOLA findings.

For local testing (against a mock server), the shipped `scope.yaml` and
`auth_profiles.yaml` already target `127.0.0.1` with dummy cookies — no edits
needed.

## 2. Run the quick pipeline

```bash
python orchestrator.py --target example.com --quick --scope scope.yaml
```

`--quick` runs 6 stages: subtakeover → reconharvest → jsreaper → headeraudit →
nuclei-harvest → triage_memory. Output lands in `./work/example.com/<timestamp>/`.

## 3. Run the deep pipeline

```bash
python orchestrator.py --target example.com --deep \
    --scope scope.yaml \
    --auth-profiles auth_profiles.yaml
```

`--deep` runs all 15+ stages including the new toolkit verifiers
(idor_crosssession, secret_verify, xss_context, spa_router, graphql_deep,
upload_probe). On any stage's fatal error, the orchestrator skips to the next
non-dependent stage rather than aborting the whole run.

## 4. Resume a previous run

```bash
python orchestrator.py --target example.com --resume
```

Stages whose output already exists are skipped. The orchestrator reads the
previous run's mode (quick / deep) from `pipeline_state.db` and uses the same
stage list.

## 5. Triage the findings

After the pipeline completes:

```bash
# Non-interactive: print the active triage queue as Markdown
python -m toolkit.verify.triage_memory \
    --input work/example.com/<timestamp>/nuclei-harvest.json \
    --print-queue

# Interactive: walk through the top 10 findings, one at a time
python -m toolkit.verify.triage_memory \
    --input work/example.com/<timestamp>/nuclei-harvest.json

# > [review|submit|reject|duplicate|skip|quit] > submit
#   ✓ writeup: reports/h1_HIGH_Possible_BOLA_abc123.md
```

Submitted findings get a HackerOne-formatted Markdown writeup in `reports/`.
Their disposition (`submitted`) is persisted in `pipeline_state.db` so future
runs filter them out of the active queue automatically.

## 6. (Optional) Continuous monitoring

```bash
# Run a quick scan every hour for every target in scope.yaml
python orchestrator.py --scope scope.yaml --watch --interval 3600

# Stop watching a specific target
python watch_daemon.py --stop example.com

# List active watches
python watch_daemon.py --list
```

The watch daemon diffs each scan against `pipeline_state.asset_history` and
emits a `WATCH_NEW_<kind>` finding for every new subdomain / JS hash / param /
endpoint / CNAME change.

## Verifying individual findings

The verifiers can run standalone against any compatible input:

```bash
# Verify BOLA candidates from apifuzz.py with two sessions
python -m toolkit.verify.idor_crosssession \
    --input work/example.com/<ts>/apifuzz.json \
    --auth-profiles auth_profiles.yaml \
    --scope scope.yaml

# Check liveness of secrets found by jsreaper.py
python -m toolkit.verify.secret_verify \
    --input work/example.com/<ts>/jsreaper.json

# Verify XSS in reflected params from paramfuzz.py
python -m toolkit.verify.xss_context \
    --input work/example.com/<ts>/paramfuzz.json \
    --scope scope.yaml
```

## What each layer does

| Layer | Tools | Purpose |
|---|---|---|
| 0 | scope_guard, auth_profiles, pipeline_state, finding | Shared infra — every tool depends on these |
| 1 | subtakeover, reconharvest | Asset discovery (subdomains, DNS) |
| 2 | jsreaper, js-extractor_3, recon_pipeline_v4, **spa_router**, gitdump | Content + JS analysis |
| 3 | headeraudit, 4xxbypass, apifuzz, paramfuzz, cloudexpose, ssrfprobe, oauthprobe, **xss_context**, **upload_probe**, **graphql_deep**, nuclei-go | Targeted testing |
| 4 | **secret_verify**, **idor_crosssession**, **anomaly_baseline** | Verification — promotes candidates to confirmed |
| 5 | nuclei-harvest, **triage_memory** | Aggregation + interactive triage |
| 6 | You, in Burp/Caido | Manual verification + submission |

Bold = new in this toolkit.

## Troubleshooting

**"scope_guard: out_of_scope"** — your `scope.yaml` doesn't include the target.
Edit `scope.yaml` and re-run.

**"auth_profiles: at least two authenticated profiles required"** —
`idor_crosssession.py` needs both `user_a` and `user_b` defined with cookies or
bearer tokens. Edit `auth_profiles.yaml`.

**"httpx required"** — install with `pip install httpx`. The toolkit uses httpx
for all live HTTP, matching the existing scripts' pattern.

**Tests failing?** Run `python -m pytest toolkit/tests/ -v` from the project
root. The test suite includes a mock HTTP server fixture for end-to-end
coverage.

## Next steps

- Read `WORKFLOW.md` for the full manual workflow (replaces this QUICKSTART for
  advanced cases).
- Read `toolkit/IMPLEMENTATION_NOTES.md` for deviations from ARCHITECTURE.md
  and the rationale behind each.
- Read `ARCHITECTURE.md` (the original spec) for the design philosophy.
