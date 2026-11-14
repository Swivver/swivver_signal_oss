# Swivver Signal OSS

An open-source track (`v1.0.0`) for the [Swivver Signal](https://swivver.ai/signal) project. Signal is an evidence-aware approach to media integrity, provenance, accessibility, and supplied-evidence verification—not a universal quality score or an automatic enforcement verdict.

## Scope boundary

This Apache-2.0 engine **does not evaluate editorial/informational content quality (`E01`–`E06`) or rank authors by credibility**. It never scores journalistic value, determines whether a creator is "credible," emits psychological/addiction diagnoses, or takes automatic enforcement action (`automatic_action` is always `"none"`, and numerical confidence `probability` is always `null`).

## Capabilities and safeguards (`v1.0.0`)

`swivver-signal-oss` is a standalone generic-media CLI and durable single-host HTTP service with zero dependency on Swivver Core, Story, Article, platform auth, PostgreSQL, MinIO, or Temporal. Core is strictly an optional external HTTP client.

- **Multi-modality technical decode (`ffmpeg-technical-v1`):**
  - **Video:** MP4/MOV/M4A/3GP and Matroska/WebM, one video stream and at most one audio stream, `10`–`600` seconds (caller-configurable or via `SIGNAL_MAX_DURATION_SECONDS`), up to `512 MiB` and `4096×4096` pixels. Measures dimensions, aspect ratio, duration, embedded subtitle track count, and timed black (`blackdetect`), static (`freezedetect`), and silent (`silencedetect`) segments with `[start_seconds, end_seconds]` evidence intervals.
  - **Standalone audio:** MP3, WAV, FLAC, M4A, OGG, and AAC, `1`–`600` seconds (`media.modality = "audio"`). Measures duration, silence intervals, mean/max volume (`dBFS`), peak-to-RMS delta (`dB`), and EBU R128 loudness range (`LU`), marking video-only metrics `"not_applicable"`.
  - **Standalone still images:** JPEG, PNG, and WebP (rejecting animated APNG/WebP), up to `4096×4096` pixels (`media.modality = "image"`). Extracts dimensions, aspect ratio, sanitized TIFF/EXIF fields (`media.exif`, omitting GPS coordinates), offline C2PA credentials, and 64-bit `dHash`, marking temporal/audio metrics `"not_applicable"`.
- **`A03` Photosensitive flash screening:** Single-pass `64×36` RGB frame scan detecting sustained `>= 4.0 Hz` opposing luminance (`>= 10%` jump) or saturated-red (`>= 20%` jump) transitions (`accessibility.flash_segments`, `accessibility.max_flash_rate_hz`, `photosensitive_flash_observed`).
- **`P01` Offline C2PA / Content Credentials (`c2pa-jumbf-v1`):** Pure-Python offline JUMBF (`c2pa`/`jumd`/`c2ma`/`c2as`/`c2cl`/`c2cs`), RFC 8949 CBOR, and `COSE_Sign1` inspector across JPEG XT `APP11` (including multi-segment `En`/`Z` reassembly), PNG `caBX`, MP4 `uuid` (`d8fec3d6-1b0e-483c-9297-5828877ec481`), and WebP `C2PA` chunks. Verifies assertion digests, `c2pa.hash.data` exclusion byte-range hashes, and embedded X.509 leaf signatures (`PS256`/`PS384`/`PS512`, `RS256`/`RS384`/`RS512`, `ES256`, `ES384`) without network calls (`valid_manifest`, `tampered_payload`, `unverified_signature`, `absent`).
- **`P04` Perceptual hash (`dhash-9x8-v1`):** Deterministic 64-bit `9×8` grayscale horizontal difference hash (`dhash_hex`) across still images and representative video keyframes (`25%`, `50%`, `75%`), plus `compute_dhash` and `hamming_distance` helpers.
- **`D01` Objective attention & pacing telemetry:** Deterministic, non-clinical editing and loudness measurements (`attention.cuts_per_min`, `attention.opening_3s_cut_count`, `attention.cut_acceleration`, `attention.loop_frame_similarity`, `attention.audio_peak_rms_delta_db`, `attention.audio_loudness_range_lu`). Intent and psychological/clinical effects are never inferred (`attention_design` remains `"unsupported"`).
- **Supplied-evidence NLI (`source-evidence-nli-v1`):** Optional local checkpoint evaluating explicit claims against supplied source passages in `en`, `pt`, and `es` using sentence-aligned sliding-window chunking (`<= max_tokens` per window with stride overlap) and exact Unicode code-point citations. Monolingual checkpoints abstain cleanly (`status: "unknown"`) on unsupported languages unless paired with `SIGNAL_MULTILINGUAL_EVIDENCE_MODEL`.
- **Per-principal quotas & TTL retention:** Configurable per-principal sliding-window rate limits (`SIGNAL_RATE_LIMIT_RPM`) returning `429` with `Retry-After`, and atomic SQLite expired-job/asset TTL reaping (`SIGNAL_RETENTION_HOURS`).

## Run locally

Requires Python 3.11+, `ffmpeg`, and `ffprobe`. The core measurement and HTTP service package has zero third-party Python runtime dependencies (`dependencies = []`).

```sh
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/signal-oss analyze /absolute/path/to/media.mp4 --output profile.json
.venv/bin/pip install '.[test]'
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Input checksum/size mismatches, inconsistent video/container timelines, animated image containers, corrupt media, and tool failures raise `MediaError` (HTTP `422` or failed job), never a clean profile.

Contracts:
- Technical profile v1.0: [signal-profile/1.0](schemas/profile-1.0.schema.json) (backward-compatible reader schema at [signal-profile/0.1](schemas/profile-0.1.schema.json))
- Supplied-evidence profile: [signal-evidence-profile/0.1](schemas/evidence-profile-0.1.schema.json)
- Standalone HTTP OpenAPI 3.1: [standalone.openapi.json](schemas/standalone.openapi.json)

## Standalone service

```sh
export SIGNAL_API_TOKEN='a-local-random-secret'
export SIGNAL_DATA_DIR='/absolute/path/to/signal-state'
export SIGNAL_RATE_LIMIT_RPM='600'
export SIGNAL_RETENTION_HOURS='168'
.venv/bin/signal-oss serve --host 127.0.0.1 --port 8765
```

Alternatively, `docker compose up --build` runs the service alone using [compose.yml](compose.yml) with a persistent named volume.

```sh
curl --fail http://127.0.0.1:8765/ready
curl --fail -H "Authorization: Bearer $SIGNAL_API_TOKEN" \
  -H 'Content-Type: application/octet-stream' --data-binary @/absolute/path/media.mp4 \
  http://127.0.0.1:8765/v1/assets
curl --fail -H "Authorization: Bearer $SIGNAL_API_TOKEN" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: my-assessment-001' \
  -d '{"asset_id":"<returned-asset-id>"}' http://127.0.0.1:8765/v1/assessments
```

`POST /v1/assets` streams at most `512 MiB`, computes SHA-256, and optionally verifies `X-Content-SHA256`. `POST /v1/assessments` returns a durable `202` receipt; `GET /v1/assessments/{id}` returns `queued|running|completed|failed`, attempts, and optional profile. `SIGNAL_API_KEYS_JSON='{"partner-a":"secret-a","partner-b":"secret-b"}'` scopes assets, jobs, and rate-limit buckets per principal. `SIGNAL_MEDIA_HOSTS` allowlists exact lowercase `host[:port]` origins for `media:{url,sha256,size_bytes}` downloads with redirects/proxies disabled.

## Optional supplied-evidence model (`en`, `pt`, `es`)

Install `.[models]` and point `SIGNAL_EVIDENCE_MODEL` (and optionally `SIGNAL_MULTILINGUAL_EVIDENCE_MODEL` or `--multilingual-evidence-model`) to local checkpoint directories containing `model.safetensors`, tokenizer files, and `release.json` (which may declare `"languages": ["en", "pt", "es"]`, defaulting to `["en"]`). Long source passages are segmented into sentence-aligned overlapping windows within `max_tokens`, preserving exact Unicode code-point offsets (`start_offset`, `end_offset`) into the original `source["text"]`.

## License

Apache-2.0. See [LICENSE](LICENSE).
