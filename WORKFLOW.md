# WORKFLOW — Bug Bounty Toolkit

Replaces the previous manual 10-step process. The orchestrator drives the
pipeline; this doc explains what each stage does, when to use `--quick` vs
`--deep`, and how to do manual follow-up after the pipeline finishes.

## Design philosophy

> **Automation is the map. Manual testing is the expedition.**

The pipeline's job is to get you to the right 10% of the haystack faster, not
to replace the decision of what's worth reporting. Concretely:

- **No tool escalates its own severity.** A tool can flag `confidence: candidate`;
  only a human (or a Layer 4 verifier with live cross-session proof) can raise
  it to `confirmed`.
- **One shared finding schema** — every tool speaks the `NormalizedFinding`
  shape natively, instead of each writing its own JSON and making
  `nuclei-harvest.py` normalize on ingest.
- **One shared scope + auth config** — no per-tool `--cookie` flags. `scope.yaml`
  and `auth_profiles.yaml` are loaded once by the orchestrator and inherited.

## Modes

### `--quick` — 6 stages, ~5 minutes per target

For initial recon or re-scans of previously-tested targets. Runs:

1. `subtakeover10.py` — subdomain discovery + takeover detection
2. `reconharvest.py` — passive recon enrichment (CT logs, wayback, etc.)
3. `jsreaper.py` — JS asset + secret + endpoint extraction
4. `headeraudit.py` — security header audit
5. `nuclei-harvest.py` — aggregate all of the above into `final.json`
6. `triage_memory.py` — produce the active triage queue

Skip `--quick` for any target with substantial API surface or modern SPA —
`--deep` is the right default.

### `--deep` — 15+ stages, 30-90 minutes per target

Full pipeline. Adds:

- `gitdump.py` — exposed .git reconstruction
- `spa_router.py` — static SPA route-table reconstruction (Next.js / Nuxt /
  React Router / Vue Router)
- `4xxbypass.py` — 4xx bypass attempts (method override, headers, path tricks)
- `apifuzz.py` — API fuzzing (BOLA, JWT none, mass-assignment, rate-limit)
- `paramfuzz.py` — hidden parameter discovery
- `ssrfprobe.py` — SSRF probing (metadata, internal, OOB)
- `oauthprobe.py` — OAuth misconfiguration (redirect takeover, state CSRF)
- `cloudexpose.py` — exposed S3 / Firebase / cloud storage
- `xss_context.py` — context-aware reflected XSS verification
- `idor_crosssession.py` — cross-session BOLA verification (needs 2 profiles)
- `secret_verify.py` — provider-side liveness check for harvested secrets
- `graphql_deep.py` — GraphQL schema recovery + batching/depth abuse
- `upload_probe.py` — file upload abuse testing (polyglot, path traversal)

`--deep` is the recommended default for any target you're seriously pursuing.

### `--resume` — continue from the last checkpoint

Skips stages whose output already exists. Useful when:

- The pipeline crashed mid-run
- You added a new tool and want to run only the new stages
- You want to re-run a single stage manually then continue the pipeline

`--resume` reads the previous run's mode from `pipeline_state.db` and uses the
same stage list.

### `--watch` — continuous monitoring

Hands off to `watch_daemon.py`. Runs `--quick` (or `--deep` with `--full-mode`)
on a schedule for every target in `scope.yaml`. Diffs each scan against
`pipeline_state.asset_history` and alerts only on genuinely new signal:

- new subdomain (subtakeover)
- new JS file hash (jsreaper)
- new param discovered (paramfuzz)
- new endpoint observed (jsreaper)
- CNAME entering a takeover-eligible state (subtakeover)

Stop a specific target with `python watch_daemon.py --stop <target>`.

## Per-stage flow

Each stage:

1. Checks if its output already exists (skip if `--resume`)
2. Calls `scope_guard.check_scope()` for every host it touches
3. Acquires a rate-limit token via `scope_guard.acquire_token()`
4. Runs the underlying tool as a subprocess (existing scripts) or Python
   module (new toolkit tools)
5. Writes output to `work/<target>/<timestamp>/<stage_name>.json`
6. Logs success/failure to `pipeline_state.scan_runs`
7. On fatal error, logs and skips to the next non-dependent stage

The orchestrator's Ctrl+C handler sets an `_interrupted` flag that lets the
current stage finish cleanly before exiting. Progress is saved to
`pipeline_state.db` so `--resume` picks up where you left off.

## Manual follow-up after the pipeline

The pipeline gets you to the right 10% of the haystack. The actual reporting
decision is yours. Recommended workflow:

### 1. Review the triage queue

```bash
cat work/<target>/<ts>/triage_queue.md
```

Findings are severity-sorted (CRITICAL → HIGH → MEDIUM → LOW → INFO).
Previously-submitted or -rejected findings are filtered out — only the active
queue is shown.

### 2. Walk through interactively

```bash
python -m toolkit.verify.triage_memory \
    --input work/<target>/<ts>/nuclei-harvest.json \
    --writeup-dir reports/
```

For each finding, type one of: `review | submit | reject | duplicate <id> |
skip | quit`. Submitting auto-generates a HackerOne-formatted writeup in
`reports/h1_<SEVERITY>_<title>_<id>.md`.

### 3. For confirmed BOLA/IDOR findings

The pipeline already verified these via `idor_crosssession.py` — they have
`confidence: confirmed` and `verified_by: idor_crosssession.py`. Look at the
finding's `evidence` field for the three-way check details (user_a response,
user_b response, body similarity) and the blast-radius estimate.

### 4. For confirmed live secrets

`secret_verify.py` already confirmed the key is live and identified the
account. Cross-reference with the JS source URL to find where it was leaked.
The finding's `raw.identity` field has the AWS ARN / GitHub login / Slack team
the key belongs to.

### 5. Manual verification in Burp / Caido

The pipeline's `curl_command` field on every finding is a copy-pasteable PoC.
Load it into Burp Repeater for manual tweaking:

- Try adjacent IDs (for BOLA)
- Try different roles (for privilege escalation)
- Try different content-types (for uploadProbe findings)
- Try different schemes (for SSRF — `gopher://`, `file://`, `dict://`)

### 6. Submit

Either use the auto-generated writeup from `triage_memory.py --writeup-dir`, or
write your own. Either way, mark the finding as `submitted` in
`pipeline_state.db` so future runs filter it out:

```bash
# Via triage_memory interactive
python -m toolkit.verify.triage_memory --input work/.../nuclei-harvest.json
# > submit

# Or via batch CSV (for CI)
echo "finding_id,disposition,note" > triage.csv
echo "abc123def456,submitted,confirmed via Burp" >> triage.csv
python -m toolkit.verify.triage_memory --input work/.../nuclei-harvest.json \
    --batch --dispositions-csv triage.csv
```

## Conditional stages

### Mobile scope (`--apk-dir`)

If the program's scope includes an Android APK, decompile it with apktool
first, then pass the decoded directory:

```bash
apktool d target.apk -o target_decoded
python orchestrator.py --target target.com --deep --apk-dir target_decoded
```

This enables the `apk_static.py` stage, which scans AndroidManifest.xml +
smali + strings.xml for exported components, hardcoded secrets, internal URLs.

### OOB callbacks (self-hosted interact.sh)

For blind-vuln-heavy targets, deploy `oob_catcher.py` on a VPS with a wildcard
DNS record pointing at it:

```bash
# On the VPS (with sudo for port 53/80)
python -m toolkit.infra_ext.oob_catcher \
    --base-domain oob.yourdomain.com \
    --state-file /var/lib/oob_catcher/state.json

# Then point ssrfprobe at it
python scripts/ssrfprobe.py --oob-domain oob.yourdomain.com ...
```

This reduces dependence on the public interact.sh instance and gives you
callback retention control.

## Failure modes + recovery

### A stage fails

The orchestrator logs the error to `pipeline_state.scan_runs.failed_stage` and
continues with the next non-dependent stage. Re-run with `--resume` to retry
just the failed stage (its output doesn't exist).

### Scope rejection

If `scope_guard.check_scope()` rejects a target, the request is logged to
`blocked.log` next to `scope.yaml` with timestamp, host, source tool, and
reason. Review this file periodically to catch false-positive rejections
(typo'd scope entries).

### Rate limit exceeded

The token-bucket blocks (up to `timeout` seconds) when the rate limit is
exhausted. If a tool times out waiting for a token, increase
`rate_limit.max_rps` or `rate_limit.max_concurrent` in `scope.yaml`. The
default (5 rps / 10 concurrent) is conservative — most programs allow more.

### DB locked

If multiple pipeline processes try to write to `pipeline_state.db`
simultaneously, you'll see `sqlite3.OperationalError: database is locked`. The
wrapper retries with a 10s timeout; if that fails, serialize your runs.

## See also

- `QUICKSTART.md` — 5-command end-to-end guide
- `toolkit/IMPLEMENTATION_NOTES.md` — deviations from ARCHITECTURE.md
- `ARCHITECTURE.md` — original design spec
- Per-tool READMEs in `toolkit/<subdir>/<tool>.README.md`
