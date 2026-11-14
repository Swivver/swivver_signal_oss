# AGENTS.md — Swivver Signal OSS (`swivver_signal_oss`)

Operating guide for agents and contributors working in `swivver_signal_oss`, the public **Apache-2.0** standalone media-measurement and supplied-evidence engine for [Swivver Signal](https://swivver.ai/signal).

Read [README.md](README.md), [pyproject.toml](pyproject.toml), and the JSON schemas under `schemas/` before modifying code. Distinguish between the published GitHub `main` branch (currently documentation and license) and the local uncommitted `0.2.0` Python implementation in this checkout.

---

## 1. Standalone Generic-Media Architecture (Zero Core Coupling)

`swivver_signal_oss` is an independently runnable generic-media analysis engine and durable HTTP job service.

- **Zero dependency on Swivver Core:** Never import, require, or assume Swivver Core code, `Story`, `Article`, `Swive`, platform user authentication/OAuth, Core's PostgreSQL schema, Redis, MinIO, or Temporal.
- **Generic media first:** Any caller can analyze an eligible local file via CLI (`signal-oss analyze`) or submit raw media bytes / allowlisted URLs via HTTP (`signal-oss serve`). Never require a caller to fabricate a `Story` or `Article` wrapper. Swivver Core is strictly an optional external HTTP client using the same public transport (`POST /v1/assets`, `POST /v1/assessments`, `GET /v1/assessments/{id}`).
- **Neutral extension boundary:** Private or downstream packages extend `swivver_signal_oss.service.Application` via `register_engine(name, engine)` and `install_evidence_engine(engine)` (and `cli.main(application_factory=...)`). Keep `swivver_signal_oss` completely neutral regarding private business policies or editorial rubrics.
- **Closed-egress & byte-bound inputs:** Direct uploads (`POST /v1/assets`) compute SHA-256 on stream and optionally verify `X-Content-SHA256`. URL inputs (`media: {url, sha256, size_bytes}`) are disabled unless the exact lowercase `host[:port]` origin is listed in `SIGNAL_MEDIA_HOSTS`; redirects, proxy inheritance, userinfo, fragments, and `file://` URLs are rejected (`NoRedirect`), and downloaded bytes are verified against declared size and SHA-256 before FFprobe/FFmpeg runs.

---

## 2. Strict Apache-2.0 OSS Scope Exclusions & Output Invariants

Keep the open-source boundary unambiguous at all times:

1. **NO editorial or informational merit scoring:** Never implement, copy, or expose `E01`–`E06` editorial rubrics (material completeness, explanatory usefulness, clarity/structure, fair representation, contribution, genre/framing honesty) or any "good content" / journalistic-value score in this repository.
2. **NO author-credibility ranking:** Never score, rank, or infer creator, journalist, or publisher trustworthiness/reputation.
3. **NO proprietary VLM/challenger prompts or commercial connectors:** Keep multimodal analyst/challenger prompts, editorial rubrics, commercial search connectors, and proprietary forensic/biometric adapters out of `swivver_signal_oss`. Do not bundle model weights, private datasets, or media fixtures in Git.
4. **Advisory, non-enforcing outputs only:**
   - Every flag MUST set `"automatic_action": "none"` and `"review_state": "unreviewed"`.
   - Every profile sets `"mode": "shadow"`, `"state": "partial"`, and `"review_state": "unreviewed"`.
   - Numerical model confidence is withheld (`"probability": null`, `"calibration_id": null`, `"status": "uncalibrated"` or `"not_applicable"`).
5. **First-class uncertainty (`unknown` / `unsupported` / `not_applicable`):**
   - Preserve `unknown`, `unsupported`, and `not_applicable` as explicit first-class states with human-readable `limitations`.
   - **Never** convert missing modalities, absent audio, unconfigured models, token-budget overflows, or unsupported categories into `"safe"`, `"clean"`, `"bad"`, `0`, or `50/100` verdicts.
   - Corrupt media, checksum/size mismatches, container/stream timeline drift, and subprocess failures/timeouts MUST raise `MediaError` (returning HTTP `422` on synchronous validation or terminal job `state: "failed"` with `profile: null`), never a clean profile. Never leak local filesystem paths or raw FFmpeg stderr tags in error messages.
6. **License & workspace hygiene:**
   - Runtime package dependencies for technical measurement remain empty (`dependencies = []` in `pyproject.toml`); any optional dependency must be compatible with `Apache-2.0`.
   - Never stage sibling repositories, credentials, `.venv/`, `.signal/`, model checkpoints, or machine-specific user-home paths in repository files.

---

## 3. Current Local 0.2 Capabilities vs. Limits

### 3.1 Technical Video Bundle (`ffmpeg-technical-v1`)
- **Contract:** `schemas/profile-0.1.schema.json` (`schema_version: "signal-profile/0.1"`), implemented in `src/swivver_signal_oss/media.py`.
- **Measured signals:** `media.duration`, `media.width`, `media.height`, `media.audio_track_count`, `accessibility.embedded_caption_track_count`, timed `technical.black_segments` (`blackdetect`), `technical.static_segments` (`freezedetect`), `technical.silent_segments` (`silencedetect`), `technical.mean_volume`, and `technical.max_volume` (`volumedetect`), with media-hash-bound `[start_seconds, end_seconds]` evidence intervals.
  - When audio is absent, `technical.silent_segments`, `technical.mean_volume`, and `technical.max_volume` return `status: "not_applicable"` (`value: null`), not silence warnings.
  - Black frames are also static; raw `technical.static_segments` counts and evidence intervals are preserved, while duplicate `static_frames_observed` flags are suppressed when black intervals cover ≥95% of the static span.
- **Explicitly `unsupported` signals in 0.2:** `safety`, `age_suitability`, `synthetic_media`, `identity`, `advertising_integrity`, `claim_support`, `rights`, `provenance`, `caption_completeness` (embedded subtitle track count cannot detect or verify burned-in captions), and `attention_design`.
- **Strict input envelope:**
  - Byte size: `1` byte to `512 MiB` (`536,870,912` bytes).
  - Container demuxers (`-format_whitelist`): `mov,matroska,webm` (MP4/MOV/MKV/WebM) over `file,pipe` protocols only.
  - Streams: exactly `1` non-attached-picture video stream and at most `1` audio stream.
  - Duration: `10`–`200` seconds (`10 <= duration <= 200.1` container tolerance; video stream duration must match container duration within `0.2s`).
  - Resolution: `1`–`4096` width and `1`–`4096` height.
  - Still images, audio-only files, PDFs/documents, and clips outside `10–200s` are out of scope and rejected with `MediaError`.

### 3.2 Optional Local Supplied-Evidence Bundle (`source-evidence-nli-v1`)
- **Contract:** `schemas/evidence-profile-0.1.schema.json` (`schema_version: "signal-evidence-profile/0.1"`), implemented in `src/swivver_signal_oss/evidence.py`.
- **Activation:** Requires optional `.[models]` (`torch`, `transformers`, `numpy`, `sentencepiece`) and `SIGNAL_EVIDENCE_MODEL` (or `--evidence-model`) pointing to a local directory containing `release.json`, tokenizer files, and `model.safetensors`. Never downloads weights from the network (`local_files_only=True`, `trust_remote_code=False`). Verifies `checkpoint_sha256` and exact `[contradiction, entailment, neutral]` label order at startup. `/v1/capabilities` advertises `source-evidence-nli-v1` only when loaded.
- **Scope & limits:**
  - Explicit `language: "en"`, `1`–`20` `sources` (`id`, `revision_id`, `text` of `1`–`64,000` code points each; `≤400,000` total code points across sources), and `1`–`20` `claims` (`1`–`4,000` code points each, `0`–`20` evidence locators per claim).
  - Evidence offsets (`start_offset`, `end_offset`) are half-open Unicode code-point indices into the exact supplied source text.
  - Pairs exceeding `release.json` `max_tokens` are **never silently truncated**; affected claims abstain (`status: "unknown"`, `label: "insufficient_evidence"`).
  - Shared fast-tokenizer and model execution are serialized under a lock for worker thread safety.
  - Performs **no** web or corpus retrieval (`coverage.retrieval = "not_performed"`) and makes **no** claim about external truth or source authority (`coverage.editorial_quality = "unsupported"`, `coverage.author_credibility = "unsupported"`).

### 3.3 Durable Single-Host SQLite Job Queue
- **Contract:** `schemas/standalone.openapi.json` (served at `/openapi.json`), implemented in `src/swivver_signal_oss/jobs.py`, `service.py`, `server.py`, and `api.py`.
- **Guarantees:** WAL-mode SQLite store in `SIGNAL_DATA_DIR` providing caller-principal isolation (`SIGNAL_API_TOKEN` or `SIGNAL_API_KEYS_JSON`), `Idempotency-Key` replay/409-conflict checks (rotating signed media URLs preserve command identity when `sha256` and `size_bytes` match), fenced worker leases (`LeaseLost` prevents stale workers from overwriting recovered jobs), bounded retries (`3` attempts before terminal `failed` / `lease_exhausted`), and SQLite triggers preventing mutation of completed results.
- **Limits:** `SIGNAL_WORKERS` `1`–`16` (default `2`), `SIGNAL_MAX_PENDING` `1`–`10,000` (default `1,000`; `429` on queue saturation, `503` on ingress saturation). Designed strictly for a **single host on a local POSIX filesystem** behind a reverse proxy—never mount `SIGNAL_DATA_DIR` on NFS/SMB or share one SQLite file across distributed hosts. `POST /v1/analyze` is deprecated synchronous compatibility only; use `POST /v1/assessments`.

---

## 4. Local CLI & Verification Commands

Run all commands from this repository root (`swivver_signal_oss/`). Requires Python 3.11+, `ffmpeg`, and `ffprobe` on `PATH`.

```sh
# 1. Optional isolated virtualenv setup
python3.11 -m venv .venv
.venv/bin/pip install -e '.[test]'

# 2. Run the full unit, contract-schema, media, evidence, and HTTP durability test suite
PYTHONPATH=src python3.11 -m unittest discover -s tests -v

# 3. Optional: also exercise a real local hash-bound NLI checkpoint if available
SIGNAL_TEST_EVIDENCE_MODEL=/path/to/evidence-nli-v1 \
  PYTHONPATH=src python3.11 -m unittest discover -s tests -v

# 4. Lint source and tests
ruff check src tests

# 5. Standalone CLI check (no Core services needed)
PYTHONPATH=src python3.11 -m swivver_signal_oss.cli --help
# Analyze an eligible 10-200s local video:
PYTHONPATH=src python3.11 -m swivver_signal_oss.cli analyze /path/to/video.mp4 --output /tmp/signal-profile.json

# 6. Run the standalone HTTP service locally
SIGNAL_API_TOKEN='replace-with-local-secret' \
SIGNAL_DATA_DIR='/tmp/signal-oss-state' \
  PYTHONPATH=src python3.11 -m swivver_signal_oss.cli serve --host 127.0.0.1 --port 8765
```

When modifying request/response structures in `src/swivver_signal_oss/api.py`, `media.py`, or `evidence.py`, keep `schemas/standalone.openapi.json`, `schemas/profile-0.1.schema.json`, and `schemas/evidence-profile-0.1.schema.json` synchronized—`tests/test_evidence.py` and `tests/test_media.py` enforce exact schema parity and Draft 2020-12 validity.
