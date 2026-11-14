# Swivver Signal OSS

An open-source track for the [Swivver Signal](https://swivver.ai/signal) project. Signal is an in-development, evidence-aware approach to short-video integrity and human-impact assessment—not a universal quality score or an automatic enforcement verdict.

## Scope boundary

This track is intended to cover **much of Signal**, but **does not evaluate content quality or rank authors by credibility**. In particular, it will not score editorial/informational value, determine whether a creator is “credible,” or present a single overall “good content” score. Content-quality evaluation here means judgment of a video's editorial/informational merit; it is distinct from technical or accessibility checks such as captions and audio intelligibility.

The broader Signal concept discusses safety, synthetic-media disclosure, identity, advertising integrity, factual claims, provenance and rights, technical/accessibility signals, and attention-design patterns. **The exact OSS feature set and interfaces have not been implemented or finalized.** The [Signal product page](https://swivver.ai/signal) describes the broader proposal, not a promise that every capability is in this OSS repository.

## Status and safeguards

The local **0.2 implementation** is an independent HTTP service with direct uploads, caller-scoped credentials, SQLite jobs/results, restart recovery and a CLI. Core is an optional client. The technical bundle measures timed black/static/silent segments, dimensions/duration, audio levels and embedded-caption tracks. An optional local NLI checkpoint proposes whether English claims match supplied source passages, with exact text citations. Safety, identity, synthetic-media detection, rights adjudication and editorial merit remain unsupported. This working tree is not a deployed or published service.

## Run locally

Requires Python 3.11+, FFmpeg and ffprobe. The measurement package has no Python runtime dependencies.

```sh
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/signal-oss analyze /absolute/path/to/video.mp4 --output profile.json
.venv/bin/pip install '.[test]'
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Supported inputs: MP4/MOV and Matroska/WebM, one video and at most one audio track,
10–200 seconds, up to 512 MiB and 4096×4096 pixels. A 0.1-second container-duration
tolerance accommodates encoding boundaries. Input checksum/size mismatches,
inconsistent video/container timelines, corrupt media and tool failures return
errors, never a clean profile. This decoder is an internal pilot: isolate it and
bound its resources when handling untrusted uploads.

The implemented contract is [signal-profile/0.1](schemas/profile-0.1.schema.json),
with `method_bundle=ffmpeg-technical-v1`, `mode=shadow`, `state=partial`, null
numerical confidence and `review_state=unreviewed`. Deliberate still images,
silence and black screens may be appropriate. Caption-track absence does not
establish absent burned-in captions. No speech intelligibility or flash-safety
measurement is implied.

## Standalone service

Requires no Core account, Story, Article, PostgreSQL, MinIO or Temporal.
The service computes asset identities and job references itself.

```sh
export SIGNAL_API_TOKEN='a-local-random-secret'
export SIGNAL_DATA_DIR='/absolute/path/to/signal-state'
.venv/bin/signal-oss serve --host 127.0.0.1 --port 8765
```

Alternatively, `docker compose up --build` runs the service alone using
[compose.yml](compose.yml), with a persistent named volume (set the token first).

```sh
curl --fail http://127.0.0.1:8765/ready
curl --fail -H "Authorization: Bearer $SIGNAL_API_TOKEN" \
  -H 'Content-Type: application/octet-stream' --data-binary @/absolute/path/video.mp4 \
  http://127.0.0.1:8765/v1/assets
# Use the actual returned asset ID:
curl --fail -H "Authorization: Bearer $SIGNAL_API_TOKEN" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: my-assessment-001' \
  -d '{"asset_id":"<returned-asset-id>"}' http://127.0.0.1:8765/v1/assessments
# Poll /v1/assessments/<returned-job-id> with the same credential.
```

`POST /v1/assets` streams at most 512 MiB, computes SHA-256 and optionally verifies
`X-Content-SHA256`. `POST /v1/assessments` returns a stable 202 receipt; GET returns
`queued|running|completed|failed`, attempts and an optional profile. The same
caller/key/input replays one job; changed input returns 409. Expired worker leases
recover work and fence late results; retries exhaust after three attempts.
Completed/input records are immutable. SQLite supports one host with a durable
local filesystem, not a network filesystem or distributed worker fleet.

`SIGNAL_API_KEYS_JSON='{"partner-a":"secret-a","partner-b":"secret-b"}'` replaces
the default token. Assets/jobs are scoped to each configured principal. These
are operator-managed service credentials; there is no signup/billing UI.
`SIGNAL_WORKERS` defaults to 2 (1–16); `SIGNAL_MAX_PENDING` to 1000 (1–10000).
Queue saturation returns 429, ingress saturation 503. State includes private
source text and signed references; protect the state directory. Automated
retention/deletion and per-principal quotas remain work.

For URL input, supply `media:{url,sha256,size_bytes}` instead of `asset_id` and set
`SIGNAL_MEDIA_HOSTS` to exact allowed lowercase `host[:port]` origins. Upload-only
operation requires no allowlist. Redirects/proxies are blocked and actual bytes
are verified. Optional `binding:{snapshot_id,input_sha256}` binds external context;
absent bindings use Signal's own job/input identity. Core uses this same API.
Renewed signed URLs do not alter idempotent media identity.

`/health` is process health; `/ready` checks storage/workers;
`/v1/capabilities` lists installed methods; authenticated `/metrics` exposes
aggregate operator counters. [OpenAPI](schemas/standalone.openapi.json) is served
at `/openapi.json`. `/v1/analyze` remains a deprecated synchronous compatibility
route for the original technical request shape.

## Optional supplied-evidence model

Install `.[models]` and set `SIGNAL_EVIDENCE_MODEL` to a local directory containing
safetensors, tokenizer/config and `release.json`. No model is bundled or downloaded
by the runtime. The release records the label mapping, token budget, identity and
checkpoint checksum. Capabilities only advertise `source-evidence-nli-v1` when
installed. This source-relative task does not score editorial merit or authors.

This bundle accepts `language:"en"`, 1–20 `sources` with IDs, revision IDs and text,
and 1–20 explicit `claims` with evidence locators. Offsets are Unicode code points,
end-exclusive. Limits: 400,000 total source code points and 20 passages per claim.
See OpenAPI for exact shapes. Over-budget pairs abstain rather than silently
truncating evidence. [signal-evidence-profile/0.1](schemas/evidence-profile-0.1.schema.json)
retains source/quote hashes, exact quotes, the model hash and proposed/unknown
outcomes. Contradiction proposals request review; numerical confidence is withheld.
Sources are supplied, not retrieved or verified as authoritative by the service.

The HTTP adapter is for a protected deployment behind a production proxy with
isolated decoding and bounded disk/CPU/memory. The private Signal workspace owns
model training and actual-data evaluations. Videos, dataset text and private
checkpoints are not bundled here. Technical results remain measurements: in 0.2,
black-covered static intervals retain raw evidence but suppress duplicate static
review warnings. Deliberate still images may be appropriate.

For collaboration on taxonomy, evaluation, and governance, see the
[Signal founding cohort](https://swivver.ai/signal#founding-cohort).

## License

Apache-2.0. See [LICENSE](LICENSE).
