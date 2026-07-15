# triage_memory

Cross-run triage queue with persistent disposition. Runs immediately after `nuclei-harvest.py` produces `final.json`. Cross-references every finding's id against `pipeline_state.db`; anything already marked `submitted` or `rejected` in a past run is filtered out of the active queue entirely — the piece `nuclei-harvest.py`'s single-run dedup was missing. Presents the top N findings (default 10, matching the 10:1 lead-to-deep-test ratio) as an interactive terminal checklist requiring a disposition before moving on. On `submit`, auto-generates a HackerOne/Bugcrowd-formatted writeup. Extends `nuclei-harvest.py`, does NOT replace it.

## Layer / Tier
Tier 1 verify. Layer 5 in the pipeline (terminal triage stage).

## Depends on
- `toolkit.infra.finding` — `NormalizedFinding`, `compute_finding_id`, `normalize_finding_dict`.
- `toolkit.infra.pipeline_state` — `PipelineState` for cross-run disposition filtering.
- Python stdlib: `argparse`, `csv`, `json`, `re`, `datetime`, `pathlib`.

## Feeds into
- HackerOne/Bugcrowd-formatted writeup `.md` files written to `--writeup-dir` (default `reports/`).
- `pipeline_state.db.findings_history` and `triage_decisions` (every disposition is audited).
- Optional `triage_queue.md` checklist written to `--output` (default `triage_queue.md`).

## Usage

```bash
# Interactive (default — top 10 findings, one at a time)
python -m toolkit.verify.triage_memory --input final.json

# CI / non-interactive (dispositions pre-filled in CSV)
python -m toolkit.verify.triage_memory --input final.json \
    --batch --dispositions-csv triage.csv

# Just print the active queue without prompting (e.g. for review)
python -m toolkit.verify.triage_memory --input final.json --print-queue --top 20
```

CSV format for `--batch`:
```
finding_id,disposition,note
abc123def456...,submitted,confirmed via Burp replay
789abc...,rejected,false positive — shared resource
```

## Library use
```python
from toolkit.verify.triage_memory import load_final_json, build_triage_entries, render_queue_md, generate_writeup
from toolkit.infra.pipeline_state import PipelineState

raw = load_final_json("final.json")
state = PipelineState("pipeline_state.db")
entries = build_triage_entries(raw, state)  # filters out submitted/rejected
print(render_queue_md(entries, top=10))
writeup = generate_writeup(entries[0].finding, format="h1")
```

## Input / Output
- **Input:** `final.json` from `nuclei-harvest.py` (or any compatible aggregator). Tolerates `{"findings": [...]}`, `{"results": [...]}`, or bare `[...]`.
- **Output:** `triage_queue.md` (Markdown checklist). On `submit`, `h1_<severity>_<title>_<id8>.md` writeups under `--writeup-dir`. CLI prints the interactive prompt or the rendered queue.
- **Side effects:** Writes to `pipeline_state.db` (every disposition recorded in both `findings_history` and `triage_decisions` audit log). No network calls.

## Key classes / functions
| Name | Purpose |
|---|---|
| `TriageEntry` | `dataclass(finding, is_new, previously_submitted, previously_rejected)` — one entry per active finding. |
| `load_final_json(path)` | Load + tolerate multiple top-level shapes. |
| `build_triage_entries(findings, state)` | Normalize each raw finding, cross-ref against DB, filter out submitted/rejected, sort by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO) then `is_new` then `last_seen`. |
| `render_queue_md(entries, top)` | Render the active queue as a Markdown checklist with PoC + remediation. |
| `generate_writeup(finding, format)` | `format="h1"` (HackerOne Markdown) or `"bc"` (Bugcrowd plain text). |
| `interactive_triage(entries, state, ...)` | Walk the user through each finding, prompt for `review | submit | reject | duplicate <id> | skip | quit`. |
| `batch_triage(entries, state, csv_path, ...)` | Apply dispositions from a pre-filled CSV (for CI). |

## Configuration
- `--input` (required): path to `final.json`.
- `--db` (default `pipeline_state.db`).
- `--top` (default 10): how many findings to walk through.
- `--output` (default `triage_queue.md`): Markdown queue file.
- `--writeup-dir` (default `reports/`): where to write H1-formatted writeups on `submit`.
- `--batch` + `--dispositions-csv` for non-interactive mode.
- `--decided-by` (default `$USER`): logged in `triage_decisions`.

## Safety notes
- Read-only against the input `final.json`. All writes go to `pipeline_state.db` and the `--writeup-dir`.
- The interactive prompt handles `EOFError` and `KeyboardInterrupt` cleanly — progress is saved after every disposition.
- No network calls. No scope enforcement needed (operates on already-collected findings).

## See also
- ARCHITECTURE.md §3.3 (triage queue) and §5 (10:1 lead-to-deep-test ratio)
- Related tools: `pipeline_state.py` (persistence), `finding.py` (NormalizedFinding), `nuclei-harvest.py` (upstream producer)
