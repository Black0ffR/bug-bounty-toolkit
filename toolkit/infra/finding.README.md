# finding

Canonical `NormalizedFinding` dataclass + helpers that every tool speaks natively, instead of each tool writing its own JSON shape. Extends `nuclei-harvest.py`'s existing `NormalizedFinding` with five new fields from ARCHITECTURE.md §3.1: `confidence` (`candidate | probable | confirmed`), `disposition` (`new | reviewed | submitted | rejected | duplicate_of`), `first_seen`, `last_seen`, `verified_by`. The first 22 fields match the existing dataclass verbatim so existing JSON consumers continue to work. `normalize_finding_dict()` is the conversion layer that takes any upstream tool's JSON shape (apifuzz, jsreaper, paramfuzz, ssrfprobe, subtakeover) and returns a canonical NormalizedFinding dict.

## Layer / Tier
Layer 0 infra. Depended on by every verify/, discover/, testers/ tool. No upstream dependencies.

## Depends on
- Python stdlib: `hashlib`, `json`, `datetime`, `dataclasses`.

## Feeds into
- `pipeline_state.upsert_finding()` expects a dict in this shape.
- `triage_memory.py` reads these via `normalize_finding_dict()` and `NormalizedFinding.from_dict()`.
- Every Tier 1-4 tool's `to_normalized*()` function emits dicts matching this shape.

## Usage

```bash
# Smoke test: emit a sample finding
python -m toolkit.infra.finding
```

## Library use
```python
from toolkit.infra.finding import NormalizedFinding, compute_finding_id, normalize_finding_dict

# Direct construction
f = NormalizedFinding(
    source_tool="idor_crosssession.py",
    host="api.target.com",
    url="https://api.target.com/v1/users/8841",
    vuln_class_key="BOLA_CONFIRMED",
    severity="CRITICAL",
    title="BOLA/IDOR confirmed cross-session",
    confidence="confirmed",
    verified_by="idor_crosssession.py",
)
f.id = compute_finding_id(f.source_tool, f.host, f.vuln_class_key, f.evidence)
print(f.to_dict())

# Convert an upstream tool's raw finding dict
canonical = normalize_finding_dict(raw_apifuzz_finding, source_tool="apifuzz.py")
```

## Input / Output
- **Input:** Either direct `NormalizedFinding(**kwargs)` construction, or a raw dict from any upstream tool passed to `normalize_finding_dict()`.
- **Output:** `to_dict()` returns a JSON-friendly dict with all fields (empty strings normalized from `None`). `from_dict(d)` is a tolerant constructor that ignores unknown keys.
- **Side effects:** None. Pure data layer.

## Key classes / functions
| Name | Purpose |
|---|---|
| `NormalizedFinding` | The canonical dataclass. 22 existing nuclei-harvest fields + 5 new ones (`confidence`, `disposition`, `first_seen`, `last_seen`, `verified_by`). `to_dict()` / `from_dict()` for JSON. |
| `compute_finding_id(source_tool, host, vuln_class_key, evidence)` | `sha256(...)` truncated to 16 hex chars. Stable across runs → enables cross-run dedup via `pipeline_state.db`. |
| `normalize_finding_dict(d, source_tool="")` | Conversion layer. Recognizes apifuzz, paramfuzz, ssrfprobe, subtakeover, jsreaper, and existing NormalizedFinding shapes. Returns canonical dict with `id`, `confidence`, `disposition` defaults filled. |
| `_fill_defaults(d)` | Internal helper — ensures every optional field has a default value before persistence. |

## Configuration
- None. No config files, no env vars.

## Safety notes
- Pure data layer — no network, no DB writes, no file I/O.
- `normalize_finding_dict()` is best-effort: if it can't recognize the source shape, it falls through to a generic passthrough that copies `host`, `url`, `severity`, `title`, `evidence` and tags `vuln_class_key="UNKNOWN"`. Never raises on unknown input.

## See also
- ARCHITECTURE.md §3.1 (NormalizedFinding schema, new fields)
- Related tools: `pipeline_state.py` (persistence), `triage_memory.py` (consumer), `nuclei-harvest.py` (original dataclass source)
