# apk_static

Android APK static analysis. Reuses the secret-regex + entropy engine from `secret_verify.py`'s normalization layer against decompiled Android artifacts: `AndroidManifest.xml` (exported components, `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`), `strings.xml` (hardcoded URLs, API keys, internal hostnames), `*.smali` files (decompiled Dalvik bytecode — same secret patterns as JS), `res/xml/network_security_config.xml` (cleartext permit, user-CA trust). This is the mobile-side equivalent of `jsreaper.py` + `secret_verify.py`. Conditional stage — only runs when a program's scope includes a mobile client.

## Layer / Tier
Tier 4 tester (conditional). Layer 3 in the pipeline.

## Depends on
- `toolkit.verify.secret_verify` — re-uses `_PROVIDER_PATTERNS`, `_looks_like_placeholder`, `_detect_provider` for secret detection in smali/strings.
- `toolkit.infra.finding` — `compute_finding_id`.
- `toolkit.infra.pipeline_state` — `PipelineState` for `upsert_finding()`.
- Python stdlib: `xml.etree.ElementTree`, `re`, `pathlib`.
- External prerequisite: `apktool` must have decompiled the APK before this tool runs. This tool does NOT shell out to `apktool` — it reads its output directory.

## Feeds into
- `apk-findings.json` — findings with `vuln_class_key` in `APK_DEBUGGABLE`, `APK_ALLOW_BACKUP`, `APK_CLEARTEXT_TRAFFIC`, `APK_USER_CA_TRUST`, `APK_NETWORK_SECURITY_CONFIG`, `APK_EXPORTED_COMPONENT`, `APK_HARDCODED_SECRET`, `APK_INTERNAL_URL`.
- `pipeline_state.db.findings_history` — every finding is upserted.
- Downstream: `secret_verify.py` (for live-key confirmation of any `APK_HARDCODED_SECRET` findings), `triage_memory.py` (triage queue).

## Usage

```bash
# Prerequisite: decompile the APK first
apktool d app.apk -o app_decoded

# Then run this tool against the decompiled directory
python -m toolkit.testers.apk_static \
    --apk-dir ./app_decoded \
    --output apk-findings.json
```

## Library use
```python
from toolkit.testers.apk_static import scan_apk_dir, to_normalized
from pathlib import Path

findings = scan_apk_dir(Path("./app_decoded"))
normalized = to_normalized(findings, apk_dir="./app_decoded")
# Each finding has: file, line, finding_type, severity, title, detail, evidence, extra
```

## Input / Output
- **Input:** A path to an apktool-decoded APK directory (`--apk-dir`). Expected layout: `AndroidManifest.xml` at root, `smali*/` directories containing `*.smali` files, `res/values/strings.xml`, optional `res/xml/network_security_config.xml`.
- **Output:** `apk-findings.json` with `scan_time`, `apk_dir`, `total_findings`, and `findings[]` (NormalizedFinding dicts with `vuln_class_key=APK_<type>`). `host` is empty (APK findings aren't host-scoped); `url` is `file://<path>`.
- **Side effects:** Reads files only. Writes to `pipeline_state.db`. No network calls — this is pure static analysis. The hardcoded-secret findings are candidates; the researcher runs `secret_verify.py` separately to confirm liveness.

## Key classes / functions
| Name | Purpose |
|---|---|
| `ApkFinding` | `dataclass(file, line, finding_type, severity, title, detail, evidence, extra)`. `finding_type` ∈ `exported_component | debuggable | allow_backup | cleartext_traffic | user_ca_trust | network_security_config | hardcoded_secret | internal_url`. |
| `_parse_manifest(manifest_path)` | Parse `AndroidManifest.xml` via `ElementTree`. Checks `application@debuggable`, `@allowBackup`, `@usesCleartextTraffic`, `@networkSecurityConfig`. Iterates `activity|activity-alias|service|receiver|provider` for `@exported=true`; flags providers with `grantUriPermissions=true` as HIGH. |
| `_scan_text_file(path, content)` | Scan smali/strings.xml line-by-line for: provider-pattern secrets (re-uses `secret_verify._PROVIDER_PATTERNS`), internal/private URLs (RFC1918 IPs + `staging|dev|internal|corp|local` hostnames). |
| `scan_apk_dir(apk_dir)` | Top-level: parse manifest, walk `smali*/*.smali` recursively, scan `res/values/strings.xml`, scan `res/xml/network_security_config.xml` for `cleartextTrafficPermitted=true` and user-CA trust. |
| `to_normalized(findings, apk_dir)` | Convert to NormalizedFinding dicts. `vuln_class_key=APK_<finding_type>`; uniform remediation. |

## Configuration
- `--apk-dir` (required): path to decompiled APK directory.
- `--output` (default `apk-findings.json`).
- `--db` (default `pipeline_state.db`).
- No scope enforcement — APK findings are not host-scoped. The hardcoded URLs found inside are leads for the researcher to test against scope manually.

## Safety notes
- Pure static analysis — no network calls, no app installation, no emulator interaction.
- Reads files only; never modifies the decompiled directory.
- The `internal_url` filter excludes common external SDKs (`googleapis.com`, `gstatic.com`, `facebook.com`, `fbcdn.net`, `apple.com`, `schema.org`, `w3.org`) to reduce noise.
- Secret detection re-uses `secret_verify._looks_like_placeholder` so documented example keys (`AKIAEXAMPLE`, etc.) are not reported.

## See also
- ARCHITECTURE.md §5.6 (mobile/APK testing) and §Conditional-stages (only when scope includes mobile)
- Related tools: `secret_verify.py` (re-uses patterns + downstream liveness check), `jsreaper.py` (web-side equivalent), `triage_memory.py` (downstream consumer)
- Prerequisite: `apktool` (external tool — `apt install apktool` or download from https://ibotpeaches.github.io/Apktool/)
