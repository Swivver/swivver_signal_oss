# Swivver Signal OSS (`v1.0.0`) — Standalone Benchmark Report (2026-11-17)

Reproducible end-to-end evaluation of the standalone **Apache-2.0** `swivver_signal_oss` media-measurement and supplied-evidence HTTP service (`POST /v1/assets`, `POST /v1/assessments`, `GET /v1/assessments/{id}`).

## 1. Headline KPIs

| Metric | Value |
| --- | ---: |
| Standalone HTTP Cases Evaluated | **30** (`30/30` passed) |
| Precision (Adverse / Hazard / Contradiction Detection) | **1.0000** |
| Recall | **1.0000** |
| Macro-F1 | **1.0000** |
| False Positive Rate (FPR) | **0.0000** |
| Abstention Accuracy (`unknown` / `insufficient_evidence`) | **1.0000** (`4` cases) |
| Invalid Container Rejection Rate | **1.0000** (`2` cases) |
| Standalone HTTP Job Latency `p50` | **0.1035 s** |
| Standalone HTTP Job Latency `p95` | **0.2904 s** |

## 2. Per-Suite Breakdown

| Suite | Cases | Precision | Recall | Macro-F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Technical Envelope & Audio/Video Quality (`black`, `static`, `silent`, `ebur128`, invalid rejection) | 8 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| Accessibility (`A03` >3 Hz Flash) & Pacing (`D01` Cuts/Accelerations) | 6 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| Provenance (`P01` Offline C2PA 2.2) & Perceptual Reuse (`P04` 64-bit `dHash`) | 6 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| Supplied-Source NLI (`en` / `pt` / `es` Supported, Contradicted & Abstention) | 10 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |

## 3. OSS Scope & Safety Invariants Verified

- **Zero external platform dependency:** Executed exclusively against `swivver_signal_oss` durable SQLite HTTP jobs.
- **Advisory shadow mode:** Every completed profile verified `mode == "shadow"`, `state == "partial"`, `review_state == "unreviewed"`, `automatic_action == "none"`, and `probability == null`.
- **First-class uncertainty:** Unsigned media without C2PA credentials reported `provenance.c2pa.value.status == "absent"` (never `"fake"` or `"tampered"`), and non-English passages on a monolingual checkpoint abstained cleanly with `status == "unknown"`.
- **OSS exclusions preserved:** Zero editorial/informational merit scoring and zero author-credibility ranking.

## 4. Reproduce

```sh
PYTHONPATH=src python3.11 tools/evaluate_oss_benchmark.py \
  --output-json docs/oss-benchmark-2026-11-17.json \
  --output-md docs/oss-benchmark-2026-11-17.md
```
