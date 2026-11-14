# AGENTS.md — Swivver Signal OSS (`swivver_signal_oss`)

Operating guide for agents and contributors working in `swivver_signal_oss`, the public **Apache-2.0** standalone media-measurement and supplied-evidence engine (`v1.0.0`) for [Swivver Signal](https://swivver.ai/signal).

Read [README.md](README.md), [pyproject.toml](pyproject.toml), and the JSON schemas under `schemas/` before modifying code. Keep published GitHub branch state separate from local commits until pushed by an operator.

---

## 1. Standalone Generic-Media Architecture (Zero Core Coupling)

`swivver_signal_oss` is an independently runnable generic-media analysis engine and durable HTTP job service.

- **Zero dependency on Swivver Core:** Never import, require, or assume Swivver Core code, `Story`, `Article`, `Swive`, platform user authentication/OAuth, Core's PostgreSQL schema, Redis, MinIO, or Temporal.
- **Generic media first:** Any caller can analyze an eligible local video, audio file, or still image via CLI (`signal-oss analyze`) or submit raw media bytes / allowlisted URLs via HTTP (`signal-oss serve`). Swivver Core is strictly an optional external HTTP client using the same public transport (`POST /v1/assets`, `POST /v1/assessments`, `GET /v1/assessments/{id}`).
- **Neutral extension boundary:** Private or downstream packages extend `swivver_signal_oss.service.Application` via `register_engine(name, engine)` and `install_evidence_engine(engine, multilingual_engine=...)` (and `cli.main(application_factory=...)`). Keep `swivver_signal_oss` completely neutral regarding private business policies or editorial rubrics.
- **Closed-egress & byte-bound inputs:** Direct uploads (`POST /v1/assets`) compute SHA-256 on stream and optionally verify `X-Content-SHA256`. URL inputs (`media: {url, sha256, size_bytes}`) are disabled unless the exact lowercase `host[:port]` origin is listed in `SIGNAL_MEDIA_HOSTS`; redirects, proxy inheritance, userinfo, fragments, and `file://` URLs are rejected (`NoRedirect`), and downloaded bytes are verified against declared size and SHA-256 before FFprobe/FFmpeg runs.

---

## 2. Strict Apache-2.0 OSS Scope Exclusions & Output Invariants

Keep the open-source boundary unambiguous at all times:

1. **NO editorial or informational merit scoring:** Never implement, copy, or expose `E01`–`E06` editorial rubrics or any "good content" / journalistic-value score in this repository.
2. **NO author-credibility ranking:** Never score, rank, or infer creator, journalist, or publisher trustworthiness/reputation.
3. **NO psychological/addiction labels or proprietary VLM/challenger prompts:** `D01` pacing metrics (`attention.*`) report strictly objective timeline and loudness measurements; never emit addiction/manipulation diagnoses. Keep multimodal analyst/challenger prompts, commercial search connectors, and proprietary forensic/biometric adapters out of `swivver_signal_oss`. Do not bundle model weights, private datasets, or media fixtures in Git.
4. **Advisory, non-enforcing outputs only:**
   - Every flag MUST set `"automatic_action": "none"` and `"review_state": "unreviewed"`.
   - Every profile sets `"mode": "shadow"`, `"state": "partial"`, and `"review_state": "unreviewed"`.
   - Numerical model confidence is withheld (`"probability": null`, `"calibration_id": null`, `"status": "uncalibrated"` or `"not_applicable"`).
5. **First-class uncertainty (`unknown` / `unsupported` / `not_applicable`):**
   - Preserve `unknown`, `unsupported`, and `not_applicable` as explicit first-class states with human-readable `limitations`.
   - **Never** convert missing modalities, absent audio, unconfigured models, unsupported model languages, or unsupported categories into `"safe"`, `"clean"`, `"bad"`, `0`, or `50/100` verdicts.
   - Corrupt media, checksum/size mismatches, container/stream timeline drift, animated image containers, and subprocess failures/timeouts MUST raise `MediaError` (HTTP `422` or terminal job `state: "failed"` with `profile: null`), never a clean profile. Never leak local filesystem paths or raw FFmpeg stderr tags in error messages.
6. **License & workspace hygiene:**
   - Runtime package dependencies for technical measurement remain empty (`dependencies = []` in `pyproject.toml`).
   - Never stage sibling repositories, credentials, `.venv/`, `.signal/`, `data/`, `.ruff_cache/`, model checkpoints, or machine-specific paths in repository files.

---

## 3. Signal OSS `1.0.0` Capabilities vs. Limits

### 3.1 Multi-Modal Technical, Provenance & Pacing Bundle (`ffmpeg-technical-v1`)
- **Contracts:** `schemas/profile-1.0.schema.json` (`schema_version: "signal-profile/1.0"`) and backward-compatible `schemas/profile-0.1.schema.json`, implemented in `src/swivver_signal_oss/media.py` and `src/swivver_signal_oss/c2pa.py`.
- **Modalities & envelopes (`1` byte to `512 MiB`):**
  - **Video (`media.modality = "video"`):** `mov,mp4,m4a,3gp,matroska,webm`, `1` non-attached-picture video stream (`1`–`4096` px) and `<= 1` audio stream, `10.0`–`600.0`s default (`min_duration_seconds`/`max_duration_seconds` or `SIGNAL_MAX_DURATION_SECONDS`, `+0.1s` container tolerance, `<= 0.2s` stream/container drift).
  - **Standalone audio (`media.modality = "audio"`):** `mp3,wav,flac,m4a,ogg,aac` (and single-audio containers), `1.0`–`600.0`s; video/visual metrics emit `status: "not_applicable"`.
  - **Still image (`media.modality = "image"`):** static `jpeg`, `png`, and `webp` (`1`–`4096` px; animated `acTL` PNG and animated `VP8X` WebP rejected); extracts sanitized `media.exif` (omitting GPS IFD `0x8825`); temporal/audio metrics emit `status: "not_applicable"`.
- **Measured signals:**
  - `media.modality`, `media.duration`, `media.width`, `media.height`, `media.aspect_ratio`, `media.exif`, `media.audio_track_count`, `accessibility.embedded_caption_track_count`.
  - `technical.black_segments`, `technical.static_segments` (suppressing duplicate `static_frames_observed` flags when black intervals cover `>= 95%` of static span), `technical.silent_segments`, `technical.mean_volume`, `technical.max_volume`.
  - `A03`: `accessibility.flash_segments`, `accessibility.max_flash_rate_hz` (`>= 4.0 Hz` opposing `>= 10%` luminance or `>= 20%` saturated-red transitions over `64×36` RGB frames; `photosensitive_flash_observed`).
  - `D01`: `attention.cuts_per_min`, `attention.opening_3s_cut_count`, `attention.cut_acceleration`, `attention.loop_frame_similarity`, `attention.audio_peak_rms_delta_db`, `attention.audio_loudness_range_lu`.
  - `P01`: `provenance.c2pa` (`c2pa-jumbf-v1` offline JUMBF/CBOR/`COSE_Sign1` verification across JPEG `APP11`, PNG `caBX`, MP4 `uuid`, WebP `C2PA`; `valid_manifest`, `tampered_payload`, `unverified_signature`, `absent`; `c2pa_tampered_payload`).
  - `P04`: `provenance.perceptual_hash` (`dhash-9x8-v1` 64-bit horizontal gradient `dhash_hex` + video keyframes; `compute_dhash` and `hamming_distance`).
- **Explicitly `unsupported` risk rubrics:** `safety`, `age_suitability`, `synthetic_media`, `identity`, `advertising_integrity`, `claim_support`, `rights`, `provenance` (CA trust-list/OCSP/authorship), `caption_completeness`, and `attention_design` (intent/clinical effects).

### 3.2 Optional Local Supplied-Evidence Bundle (`source-evidence-nli-v1`)
- **Contract:** `schemas/evidence-profile-0.1.schema.json`, implemented in `src/swivver_signal_oss/evidence.py`.
- **Capabilities:** Supports `language` in `("en", "pt", "es")`, `1`–`20` `sources` (`<= 64,000` code points each, `<= 400,000` total), and `1`–`20` `claims`. Long passages exceeding `max_tokens` are segmented into sentence-aligned sliding windows with stride overlap (`chunk_passage`), aggregating window-level entailment/contradiction scores while preserving exact Unicode code-point offsets (`start_offset`, `end_offset`) into `source["text"]`. Monolingual checkpoints abstain cleanly (`status: "unknown"`) on unsupported languages unless `SIGNAL_MULTILINGUAL_EVIDENCE_MODEL` / `--multilingual-evidence-model` is configured or `release.json` declares `"languages"`.

### 3.3 Durable Single-Host SQLite Job Queue, Quotas & TTL Reaper
- **Contract:** `schemas/standalone.openapi.json` (served at `/openapi.json`), implemented in `src/swivver_signal_oss/jobs.py`, `service.py`, `server.py`, and `api.py`.
- **Quotas & Retention:** `SlidingWindowRateLimiter` enforces `SIGNAL_RATE_LIMIT_RPM` per principal (`429` + `Retry-After`, `signal_rate_limited_total`), and `Store.reap` / background `signal-reaper` enforces `SIGNAL_RETENTION_HOURS` over terminal jobs and unreferenced asset blobs (`signal_reaped_assessments_total`, `signal_reaped_assets_total`) while preserving SQLite immutability triggers outside `reap()`.

---

## 4. Local CLI & Verification Commands

Run all commands from this repository root (`swivver_signal_oss/`). Requires Python 3.11+, `ffmpeg`, and `ffprobe` on `PATH`.

```sh
# 1. Run full unit, contract-schema, C2PA, media, evidence, and HTTP durability test suite
PYTHONPATH=src python3.11 -m unittest discover -s tests -v

# 2. Lint source and tests
ruff check src tests

# 3. Standalone CLI analysis (video, audio, or still image)
PYTHONPATH=src python3.11 -m swivver_signal_oss.cli analyze /path/to/media.mp4 --output /tmp/signal-profile.json

# 4. Run standalone HTTP service locally
SIGNAL_API_TOKEN='replace-with-local-secret' \
SIGNAL_DATA_DIR='/tmp/signal-oss-state' \
  PYTHONPATH=src python3.11 -m swivver_signal_oss.cli serve --host 127.0.0.1 --port 8765
```

Keep `schemas/standalone.openapi.json`, `schemas/profile-1.0.schema.json`, `schemas/profile-0.1.schema.json`, and `schemas/evidence-profile-0.1.schema.json` synchronized whenever `api.py`, `media.py`, or `evidence.py` changes.
