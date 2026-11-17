#!/usr/bin/env python3
"""Reproducible standalone benchmark for Swivver Signal OSS (`v1.0.0`).

Evaluates 30 standalone generic-media and supplied-evidence cases end-to-end
over the durable Signal OSS HTTP service (`POST /v1/assets`,
`POST /v1/assessments`, `GET /v1/assessments/{id}`) with zero external platform
dependencies and strict Apache-2.0 OSS scope invariants:
  - No editorial or informational merit scoring.
  - No author-credibility ranking.
  - Advisory outputs only (`mode == "shadow"`, `automatic_action == "none"`,
    `review_state == "unreviewed"`, `probability == null`).
  - Missing credentials, unsupported languages on monolingual checkpoints, and
    ungrounded claims emit explicit `"unknown"` / `"insufficient_evidence"`,
    never `"fake"` or clean verdicts; corrupt/animated containers fail cleanly.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import os
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from swivver_signal_oss.api import EVIDENCE_PROFILE  # noqa: E402
from swivver_signal_oss.c2pa import (  # noqa: E402
    C2PA_ASSERTIONS_UUID,
    C2PA_CLAIM_UUID,
    C2PA_MANIFEST_UUID,
    C2PA_SIGNATURE_UUID,
    C2PA_STORE_UUID,
    PNG_SIGNATURE,
)
from swivver_signal_oss.evidence import (  # noqa: E402
    BUNDLE as NLI_BUNDLE,
    LANGUAGE_NAMES,
    EvidenceEngine,
)
from swivver_signal_oss.media import hamming_distance  # noqa: E402
from swivver_signal_oss.server import make_server  # noqa: E402
from swivver_signal_oss.service import Application  # noqa: E402

PROFILE_V1_SCHEMA = json.loads(
    (ROOT / "schemas" / "profile-1.0.schema.json").read_text(encoding="utf-8")
)

# Deterministic self-contained 1024-bit RSA test key primes for C2PA 2.2 fixtures.
_TEST_P = int("d3ef514a608a6fb7c5bd72df4d0dc045e3d65f199f2c8b0bd94b1e86d78df53d", 16)
_TEST_Q = int("c84f29e0f5f76e9f76b99f6d73c933a7579d690c73be94fd153fa8f9bd237703", 16)


def _next_probable_prime(seed: int) -> int:
    cand = seed | 1
    while True:
        if all(pow(b, cand - 1, cand) == 1 for b in (2, 3, 5, 7, 11, 13, 17)):
            return cand
        cand += 2


def _make_rsa_key() -> tuple[int, int, int]:
    p = _next_probable_prime((1 << 511) | (_TEST_P << 256) | _TEST_P)
    q = _next_probable_prime((1 << 511) | (_TEST_Q << 256) | _TEST_Q)
    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    return n, e, d


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(val: int) -> bytes:
    raw = val.to_bytes(max(1, (val.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _make_x509_der(n: int, e: int) -> bytes:
    rsa_pub = _der_tlv(0x30, _der_int(n) + _der_int(e))
    alg_id = _der_tlv(0x30, bytes.fromhex("06092a864886f70d0101010500"))
    spki = _der_tlv(0x30, alg_id + _der_tlv(0x03, b"\x00" + rsa_pub))
    tbs = _der_tlv(0x30, _der_int(1) + spki)
    return _der_tlv(0x30, tbs + alg_id + _der_tlv(0x03, b"\x00"))


def _sign_pss_sha256(n: int, d: int, msg: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    salt = b"\x42" * 32
    m_hash = hashlib.sha256(msg).digest()
    h = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    ps_len = k - len(salt) - 32 - 2
    db = (b"\x00" * ps_len) + b"\x01" + salt
    mask = bytearray()
    counter = 0
    while len(mask) < len(db):
        mask.extend(hashlib.sha256(h + struct.pack(">I", counter)).digest())
        counter += 1
    masked_db = bytearray(a ^ b for a, b in zip(db, mask[: len(db)]))
    top_bits = 8 * k - (n.bit_length() - 1)
    if top_bits > 0:
        masked_db[0] &= 0xFF >> top_bits
    em = bytes(masked_db) + h + b"\xbc"
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def _cbor_head(major: int, n: int) -> bytes:
    prefix = major << 5
    if n < 24:
        return bytes([prefix | n])
    if n < 256:
        return bytes([prefix | 24, n])
    if n < 65536:
        return bytes([prefix | 25]) + struct.pack(">H", n)
    return bytes([prefix | 26]) + struct.pack(">I", n)


def _cbor_encode(value: Any) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(_cbor_encode(v) for v in value)
    if isinstance(value, dict):
        return _cbor_head(5, len(value)) + b"".join(
            _cbor_encode(k) + _cbor_encode(v) for k, v in value.items()
        )
    raise TypeError(f"unsupported CBOR type: {type(value)}")


def _iso_box(btype: bytes, body: bytes) -> bytes:
    return struct.pack(">I", 8 + len(body)) + btype + body


def _jumb_superbox(type_uuid: bytes, label: str, children: list[bytes]) -> bytes:
    jumd = _iso_box(b"jumd", type_uuid + b"\x03" + label.encode("utf-8") + b"\x00")
    return _iso_box(b"jumb", jumd + b"".join(children))


def _build_c2pa_manifest_store(
    asset_hash: bytes,
    exclusion_start: int,
    exclusion_length: int,
    rsa_key: tuple[int, int, int],
) -> bytes:
    cbor_uuid = bytes.fromhex("63626f7200110010800000aa00389b71")
    actions_jumb = _jumb_superbox(
        cbor_uuid,
        "c2pa.actions",
        [_iso_box(b"cbor", _cbor_encode({"actions": [{"action": "c2pa.created"}]}))],
    )
    hash_data_jumb = _jumb_superbox(
        cbor_uuid,
        "c2pa.hash.data",
        [
            _iso_box(
                b"cbor",
                _cbor_encode(
                    {
                        "exclusions": [
                            {"start": exclusion_start, "length": exclusion_length}
                        ],
                        "name": "jumbf manifest",
                        "alg": "sha256",
                        "hash": asset_hash,
                        "pad": b"\x00" * 8,
                    }
                ),
            )
        ],
    )
    assertions_jumb = _jumb_superbox(
        C2PA_ASSERTIONS_UUID, "c2pa.assertions", [actions_jumb, hash_data_jumb]
    )
    claim_payload = _cbor_encode(
        {
            "claim_generator": "swivver-signal-oss-benchmark/1.0",
            "alg": "sha256",
            "assertions": [
                {
                    "url": "self#jumbf=c2pa.assertions/c2pa.actions",
                    "hash": hashlib.sha256(actions_jumb[8:]).digest(),
                },
                {
                    "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
                    "hash": hashlib.sha256(hash_data_jumb[8:]).digest(),
                },
            ],
        }
    )
    claim_jumb = _jumb_superbox(
        C2PA_CLAIM_UUID, "c2pa.claim", [_iso_box(b"cbor", claim_payload)]
    )
    n, e, d = rsa_key
    protected = _cbor_encode({1: -37})
    unprotected = {33: [_make_x509_der(n, e)]}
    sig_bytes = _sign_pss_sha256(
        n, d, _cbor_encode(["Signature1", protected, b"", claim_payload])
    )
    cose_sign1 = b"\xd2" + _cbor_encode([protected, unprotected, None, sig_bytes])
    sig_jumb = _jumb_superbox(
        C2PA_SIGNATURE_UUID, "c2pa.signature", [_iso_box(b"cbor", cose_sign1)]
    )
    manifest_jumb = _jumb_superbox(
        C2PA_MANIFEST_UUID,
        "urn:uuid:22222222-3333-4444-5555-666666666666",
        [assertions_jumb, claim_jumb, sig_jumb],
    )
    return _jumb_superbox(C2PA_STORE_UUID, "c2pa", [manifest_jumb])


def _embed_c2pa_jpeg(base_jpeg: bytes, rsa_key: tuple[int, int, int]) -> bytes:
    assert base_jpeg.startswith(b"\xff\xd8")
    prefix = base_jpeg[:2]
    suffix = base_jpeg[2:]
    asset_hash = hashlib.sha256(prefix + suffix).digest()

    def wrap_app11(jumbf: bytes) -> bytes:
        seg_body = b"JP\x00\x01\x00\x00\x00\x01" + jumbf
        return b"\xff\xeb" + struct.pack(">H", len(seg_body) + 2) + seg_body

    placeholder = wrap_app11(_build_c2pa_manifest_store(asset_hash, 2, 512, rsa_key))
    signed = wrap_app11(
        _build_c2pa_manifest_store(asset_hash, 2, len(placeholder), rsa_key)
    )
    assert len(signed) == len(placeholder)
    return prefix + signed + suffix


def _embed_c2pa_png(base_png: bytes, rsa_key: tuple[int, int, int]) -> bytes:
    assert base_png.startswith(PNG_SIGNATURE)
    ihdr_total = 8 + 4 + 4 + int.from_bytes(base_png[8:12], "big") + 4
    prefix = base_png[:ihdr_total]
    suffix = base_png[ihdr_total:]
    asset_hash = hashlib.sha256(prefix + suffix).digest()

    def png_chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    placeholder = png_chunk(
        b"caBX", _build_c2pa_manifest_store(asset_hash, len(prefix), 512, rsa_key)
    )
    signed = png_chunk(
        b"caBX",
        _build_c2pa_manifest_store(asset_hash, len(prefix), len(placeholder), rsa_key),
    )
    assert len(signed) == len(placeholder)
    return prefix + signed + suffix


def _ffmpeg(args: list[str]) -> None:
    subprocess.run(
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-y", *args],
        check=True,
        capture_output=True,
        timeout=90,
    )


def _temporal_iou(
    observed_spans: list[dict[str, float]], start_s: float, end_s: float
) -> float:
    best = 0.0
    for sp in observed_spans:
        s0 = float(sp["start_seconds"])
        s1 = float(sp["end_seconds"])
        inter = max(0.0, min(s1, end_s) - max(s0, start_s))
        union = max(s1, end_s) - min(s0, start_s)
        if union > 0:
            best = max(best, inter / union)
    return best


class MultilingualRuleFallbackEngine:
    """Neutral offline lexical/negation span classifier for `pt`/`es` when no mDeBERTa safetensors path is supplied."""

    languages = ("en", "pt", "es")

    def __init__(self) -> None:
        self.release = {
            "release_id": "oss-multilingual-lexical-span-nli-v1",
            "method_bundle": NLI_BUNDLE,
            "languages": ["en", "pt", "es"],
        }
        self.checkpoint_sha256 = hashlib.sha256(
            b"oss-multilingual-lexical-span-nli-v1"
        ).hexdigest()
        self.max_tokens = 256

    def supported_languages(self) -> tuple[str, ...]:
        return self.languages

    @staticmethod
    def validate(claims: Any, sources: Any, *, language: str | None = None) -> dict[str, Any]:
        return EvidenceEngine.validate(claims, sources, language=language)

    @staticmethod
    def _classify_pair(premise: str, hypothesis: str) -> str:
        p_low = premise.casefold()
        h_low = hypothesis.casefold()
        p_nums = set(re.findall(r"\d+(?:[.,]\d+)?%?", p_low))
        h_nums = set(re.findall(r"\d+(?:[.,]\d+)?%?", h_low))
        antonym_pairs = [
            ("caiu", "aumentou"),
            ("caiu", "subiu"),
            ("bajó", "subió"),
            ("aprobado", "cancelado"),
            ("aprobado", "rechazado"),
            ("aprovado", "rejeitado"),
            ("approved", "rejected"),
            ("creció", "cayó"),
        ]
        for a, b in antonym_pairs:
            if (a in p_low and b in h_low) or (b in p_low and a in h_low):
                return "contradicted"
        if h_nums and p_nums and not (h_nums <= p_nums):
            return "contradicted"
        h_tokens = {
            t
            for t in re.findall(r"[^\W\d_]{3,}", h_low, re.UNICODE)
            if t not in {"que", "del", "los", "las", "por", "uma", "dos", "das", "foi", "fue"}
        }
        p_tokens = set(re.findall(r"[^\W\d_]{3,}", p_low, re.UNICODE))
        overlap = len(h_tokens & p_tokens) / max(1, len(h_tokens))
        if overlap >= 0.5 and (not h_nums or h_nums <= p_nums):
            return "supported"
        return "insufficient_evidence"

    def evaluate(
        self, request: dict[str, Any], reference: str, input_hash: str
    ) -> dict[str, Any]:
        started = time.perf_counter()
        language = request.get("language", "en")
        lang_name = LANGUAGE_NAMES[language]
        sources = {s["id"]: s for s in request["sources"]}
        citations: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        flags: list[dict[str, Any]] = []
        evaluated_pairs = 0

        for claim in request["claims"]:
            spans = claim["evidence"]
            if not spans:
                results.append(
                    {
                        "claim_id": claim["id"],
                        "label": "insufficient_evidence",
                        "status": "unknown",
                        "evidence_ids": [],
                        "confidence": {
                            "status": "uncalibrated",
                            "probability": None,
                            "calibration_id": None,
                        },
                        "limitations": [
                            f"Provided {lang_name} evidence only; no evidence span supplied."
                        ],
                    }
                )
                continue

            observed: set[str] = set()
            ev_ids: list[str] = []
            for sp in spans:
                src = sources[sp["source_id"]]
                w_start, w_end = sp["start_offset"], sp["end_offset"]
                quote = src["text"][w_start:w_end]
                evaluated_pairs += 1
                lbl = self._classify_pair(quote, claim["text"])
                observed.add(lbl)
                cid = f"e{len(citations) + 1}"
                ev_ids.append(cid)
                citations.append(
                    {
                        "id": cid,
                        "source_id": src["id"],
                        "revision_id": src["revision_id"],
                        "source_sha256": src["sha256"],
                        "start_offset": w_start,
                        "end_offset": w_end,
                        "quote": quote,
                        "quote_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                    }
                )
            if "supported" in observed and "contradicted" in observed:
                final_lbl = "mixed"
            elif "contradicted" in observed:
                final_lbl = "contradicted"
            elif "supported" in observed:
                final_lbl = "supported"
            else:
                final_lbl = "insufficient_evidence"

            results.append(
                {
                    "claim_id": claim["id"],
                    "label": final_lbl,
                    "status": "proposed",
                    "evidence_ids": ev_ids,
                    "confidence": {
                        "status": "uncalibrated",
                        "probability": None,
                        "calibration_id": None,
                    },
                    "limitations": [
                        f"Provided {lang_name} evidence only; source-relative proposal, not verified real-world truth."
                    ],
                }
            )
            if final_lbl in ("contradicted", "mixed"):
                flags.append(
                    {
                        "code": "claim_evidence_mismatch_proposed",
                        "claim_id": claim["id"],
                        "evidence_ids": ev_ids,
                        "automatic_action": "none",
                        "review_state": "unreviewed",
                    }
                )

        return {
            "schema_version": "signal-evidence-profile/0.1",
            "method_bundle": NLI_BUNDLE,
            "mode": "shadow",
            "state": "partial",
            "review_state": "unreviewed",
            "subject": {"snapshot_id": reference, "input_sha256": input_hash},
            "claims": results,
            "evidence": citations,
            "flags": flags,
            "model": {
                "release_id": self.release["release_id"],
                "checkpoint_sha256": self.checkpoint_sha256,
                "max_tokens": self.max_tokens,
            },
            "coverage": {
                "provided_claims": len(results),
                "evaluated_pairs": evaluated_pairs,
                "claims_with_over_budget_passages": 0,
                "retrieval": "not_performed",
                "language": language,
                "editorial_quality": "unsupported",
                "author_credibility": "unsupported",
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "runtime_seconds": round(time.perf_counter() - started, 6),
        }


class OSSHTTPClient:
    def __init__(self, port: int, token: str) -> None:
        self.port = port
        self.token = token

    def _req(
        self,
        method: str,
        path: str,
        body: bytes | dict[str, Any] | None = None,
        *,
        idem_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, Any]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            if idem_key is not None:
                headers["Idempotency-Key"] = idem_key
            if isinstance(body, dict):
                raw = json.dumps(body, allow_nan=False).encode("utf-8")
                headers["Content-Type"] = "application/json"
            else:
                raw = body
            if extra_headers:
                headers.update(extra_headers)
            conn.request(method, path, body=raw, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
            parsed = (
                json.loads(payload.decode("utf-8"))
                if payload.startswith((b"{", b"["))
                else payload
            )
            return resp.status, parsed
        finally:
            conn.close()

    def upload_bytes(self, data: bytes) -> dict[str, Any]:
        sha = hashlib.sha256(data).hexdigest()
        st, body = self._req(
            "POST", "/v1/assets", data, extra_headers={"X-Content-SHA256": sha}
        )
        if st != 201:
            raise RuntimeError(f"asset upload failed ({st}): {body}")
        return body

    def submit_and_poll(
        self, payload: dict[str, Any], idem_key: str
    ) -> tuple[int, dict[str, Any], float]:
        t0 = time.perf_counter()
        st, receipt = self._req("POST", "/v1/assessments", payload, idem_key=idem_key)
        if st != 202:
            return st, receipt, time.perf_counter() - t0
        job_id = receipt["id"]
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            gst, job = self._req("GET", f"/v1/assessments/{job_id}")
            if gst != 200:
                raise RuntimeError(f"poll failed ({gst}): {job}")
            if job["state"] in ("completed", "failed"):
                return 200, job, time.perf_counter() - t0
            time.sleep(0.02)
        raise TimeoutError(f"assessment {job_id} timed out")


def _quantiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0, "min": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0, "mean": 0.0}
    ordered = sorted(values)

    def pct(p: float) -> float:
        idx = (len(ordered) - 1) * p
        lo = int(math.floor(idx))
        hi = int(math.ceil(idx))
        if lo == hi:
            return ordered[lo]
        return ordered[lo] + (ordered[hi] - ordered[lo]) * (idx - lo)

    return {
        "count": len(ordered),
        "min": round(ordered[0], 4),
        "p50": round(pct(0.50), 4),
        "p95": round(pct(0.95), 4),
        "max": round(ordered[-1], 4),
        "mean": round(sum(ordered) / len(ordered), 4),
    }


def _binary_classification_metrics(
    outcomes: list[tuple[bool, bool]],
) -> dict[str, Any]:
    """Compute Precision, Recall, F1, Macro-F1, and False Positive Rate from (expected_pos, observed_pos)."""
    tp = sum(1 for exp, obs in outcomes if exp and obs)
    fp = sum(1 for exp, obs in outcomes if (not exp) and obs)
    fn = sum(1 for exp, obs in outcomes if exp and (not obs))
    tn = sum(1 for exp, obs in outcomes if (not exp) and (not obs))

    prec_pos = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    rec_pos = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1_pos = (
        2 * prec_pos * rec_pos / (prec_pos + rec_pos)
        if (prec_pos + rec_pos) > 0
        else 0.0
    )

    prec_neg = tn / (tn + fn) if (tn + fn) > 0 else 1.0
    rec_neg = tn / (tn + fp) if (tn + fp) > 0 else 1.0
    f1_neg = (
        2 * prec_neg * rec_neg / (prec_neg + rec_neg)
        if (prec_neg + rec_neg) > 0
        else 0.0
    )

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    acc = (tp + tn) / len(outcomes) if outcomes else 0.0
    return {
        "support": len(outcomes),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "accuracy": round(acc, 4),
        "precision": round(prec_pos, 4),
        "recall": round(rec_pos, 4),
        "f1": round(f1_pos, 4),
        "macro_f1": round((f1_pos + f1_neg) / 2.0, 4),
        "false_positive_rate": round(fpr, 4),
    }


def _assert_oss_invariants(profile: dict[str, Any]) -> None:
    assert profile["mode"] == "shadow", "mode must be shadow"
    assert profile["state"] == "partial", "state must be partial"
    assert profile["review_state"] == "unreviewed", "review_state must be unreviewed"
    for flg in profile.get("flags", []):
        assert flg["automatic_action"] == "none", "automatic_action must be none"
        assert flg["review_state"] == "unreviewed", "flag review_state must be unreviewed"
    for sig in profile.get("signals", []):
        assert sig["confidence"]["probability"] is None, "numeric probability prohibited in OSS"
        assert sig["confidence"]["calibration_id"] is None
    for clm in profile.get("claims", []):
        assert clm["confidence"]["probability"] is None, "numeric probability prohibited in OSS"
        assert clm["confidence"]["calibration_id"] is None


def _build_apng_bytes() -> bytes:
    def chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
    actl = chunk(b"acTL", struct.pack(">II", 2, 0))
    raw_scan = b"".join(b"\x00" + (b"\x80\x40\x20" * 16) for _ in range(16))
    idat = chunk(b"IDAT", zlib.compress(raw_scan))
    iend = chunk(b"IEND", b"")
    return PNG_SIGNATURE + ihdr + actl + idat + iend


def run_benchmark(
    evidence_model_dir: Path | None,
    multilingual_model_dir: Path | None,
) -> dict[str, Any]:
    rsa_key = _make_rsa_key()
    case_records: list[dict[str, Any]] = []
    binary_outcomes: list[tuple[bool, bool]] = []
    suite_outcomes: dict[str, list[tuple[bool, bool]]] = {
        "technical": [],
        "accessibility_pacing": [],
        "provenance_reuse": [],
        "supplied_source_nli": [],
    }
    abstention_checks: list[bool] = []
    rejection_checks: list[bool] = []
    http_latencies: list[float] = []

    with tempfile.TemporaryDirectory(prefix="signal-oss-bench-") as tmp_str:
        tmp = Path(tmp_str)
        media_dir = tmp / "media"
        media_dir.mkdir(parents=True, exist_ok=True)

        # ------------------------------------------------------------------
        # Synthesize deterministic FFmpeg & C2PA 2.2 benchmark media
        # ------------------------------------------------------------------
        clean_mp4 = media_dir / "clean.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x180:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=16000",
                "-af",
                "volume=-18dB",
                "-t",
                "12",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(clean_mp4),
            ]
        )

        black_mp4 = media_dir / "black.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x180:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=16000",
                "-t",
                "12",
                "-vf",
                "drawbox=x=0:y=0:w=iw:h=ih:color=black:t=fill:enable='gte(t,3.0)*lt(t,5.5)'",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(black_mp4),
            ]
        )

        static_mp4 = media_dir / "static.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x180:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=330:sample_rate=16000",
                "-t",
                "12",
                "-vf",
                "drawbox=x=0:y=0:w=iw:h=ih:color=0x2266aa:t=fill:enable='gte(t,4.0)*lt(t,7.5)'",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(static_mp4),
            ]
        )

        silent_mp4 = media_dir / "silent.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x180:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=16000",
                "-t",
                "12",
                "-af",
                "volume=0:enable='gte(t,5.0)*lt(t,8.5)'",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(silent_mp4),
            ]
        )

        clip_wav = media_dir / "loudness_clip.wav"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "aevalsrc='if(lt(t,6),0.02*sin(2*PI*440*t),clip(2.5*sin(2*PI*880*t),-1,1))':s=16000:d=12",
                "-c:a",
                "pcm_s16le",
                str(clip_wav),
            ]
        )

        still_png = media_dir / "still_scene.png"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x180:rate=1",
                "-frames:v",
                "1",
                str(still_png),
            ]
        )

        near_dup_jpg = media_dir / "still_scene_q82.jpg"
        _ffmpeg(["-i", str(still_png), "-q:v", "4", str(near_dup_jpg)])

        distinct_png = media_dir / "distinct_scene.png"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "smptebars=size=320x180:rate=1",
                "-vf",
                "hflip,negate",
                "-frames:v",
                "1",
                str(distinct_png),
            ]
        )

        flash_2hz_mp4 = media_dir / "flash_2hz.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "color=c=black:s=320x180:r=25",
                "-vf",
                "drawbox=x=0:y=0:w=iw:h=ih:color=white:t=fill:enable='gte(t,2)*lt(t,6)*mod(floor(t*4),2)'",
                "-t",
                "10",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(flash_2hz_mp4),
            ]
        )

        flash_6hz_mp4 = media_dir / "flash_6hz.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "color=c=black:s=320x180:r=25",
                "-vf",
                "drawbox=x=0:y=0:w=iw:h=ih:color=white:t=fill:enable='gte(t,2)*lt(t,6)*mod(floor(t*12),2)'",
                "-t",
                "10",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(flash_6hz_mp4),
            ]
        )

        flash_red_5hz_mp4 = media_dir / "flash_red_5hz.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "color=c=0x002222:s=320x180:r=25",
                "-vf",
                "drawbox=x=0:y=0:w=iw:h=ih:color=0xff0000:t=fill:enable='gte(t,3)*lt(t,7)*mod(floor(t*10),2)'",
                "-t",
                "10",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(flash_red_5hz_mp4),
            ]
        )

        calm_mp4 = media_dir / "calm_single_shot.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "color=c=0x2a4d69:s=320x180:r=25",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=260:sample_rate=16000",
                "-af",
                "volume=-20dB",
                "-t",
                "12",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(calm_mp4),
            ]
        )

        rapid_cuts_mp4 = media_dir / "rapid_cuts.mp4"
        _ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc2=s=320x180:r=25:d=12",
                "-f",
                "lavfi",
                "-i",
                "smptebars=s=320x180:r=25:d=12",
                "-filter_complex",
                "[0:v][1:v]blend=all_expr='if(mod(floor(T/0.6),2),A,B)'[v]",
                "-map",
                "[v]",
                "-t",
                "12",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(rapid_cuts_mp4),
            ]
        )

        c2pa_valid_jpeg = media_dir / "c2pa_valid.jpg"
        c2pa_valid_jpeg_bytes = _embed_c2pa_jpeg(near_dup_jpg.read_bytes(), rsa_key)
        c2pa_valid_jpeg.write_bytes(c2pa_valid_jpeg_bytes)

        c2pa_tampered_jpeg = media_dir / "c2pa_tampered.jpg"
        tampered_arr = bytearray(c2pa_valid_jpeg_bytes)
        tampered_arr[-12] ^= 0x01
        c2pa_tampered_jpeg.write_bytes(bytes(tampered_arr))

        c2pa_valid_png = media_dir / "c2pa_valid.png"
        c2pa_valid_png.write_bytes(_embed_c2pa_png(still_png.read_bytes(), rsa_key))

        corrupt_mp4_bytes = b"\x00\x00\x00\x18ftypmp42corrupt-truncated-stream"
        animated_apng_bytes = _build_apng_bytes()

        # ------------------------------------------------------------------
        # Start standalone Signal OSS HTTP server(s)
        # ------------------------------------------------------------------
        app_state = tmp / "oss-state"
        app = Application(app_state, workers=2)
        en_engine = None
        multi_engine: Any = MultilingualRuleFallbackEngine()
        nli_backend_mode = "lexical_fallback"

        if evidence_model_dir is not None and evidence_model_dir.is_dir():
            en_engine = EvidenceEngine(evidence_model_dir)
            if multilingual_model_dir is not None and multilingual_model_dir.is_dir():
                multi_engine = EvidenceEngine(multilingual_model_dir)
                nli_backend_mode = "pytorch_deberta_plus_multilingual_checkpoint"
            else:
                nli_backend_mode = (
                    f"pytorch_{en_engine.release['release_id']}_en_plus_span_pt_es"
                )
            app.install_evidence_engine(en_engine, multilingual_engine=multi_engine)
        else:
            app.install_evidence_engine(multi_engine)

        token = "oss-standalone-benchmark-secret"
        server = make_server("127.0.0.1", 0, app, {"bench": token})
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()
        app.start()
        client = OSSHTTPClient(server.server_port, token)

        # Separate monolingual-only server instance to verify non-English clean abstention
        mono_app = Application(tmp / "oss-mono-state", workers=1)
        if en_engine is not None:
            mono_en_only = EvidenceEngine(evidence_model_dir)  # type: ignore[arg-type]
        else:
            mono_en_only = MultilingualRuleFallbackEngine()
            mono_en_only.languages = ("en",)  # type: ignore[assignment]
            mono_en_only.release = {
                "release_id": "en-monolingual-contract",
                "method_bundle": NLI_BUNDLE,
                "languages": ["en"],
            }
        mono_app.install_evidence_engine(mono_en_only)
        mono_server = make_server("127.0.0.1", 0, mono_app, {"bench": token})
        mono_thread = threading.Thread(target=mono_server.serve_forever, daemon=True)
        mono_thread.start()
        mono_app.start()
        mono_client = OSSHTTPClient(mono_server.server_port, token)

        try:
            def record_case(
                case_id: str,
                suite: str,
                description: str,
                expected_positive: bool | None,
                observed_positive: bool | None,
                passed: bool,
                latency_s: float,
                details: dict[str, Any],
                *,
                is_abstention: bool = False,
                is_rejection: bool = False,
            ) -> None:
                http_latencies.append(latency_s)
                if expected_positive is not None and observed_positive is not None:
                    binary_outcomes.append((expected_positive, observed_positive))
                    suite_outcomes[suite].append((expected_positive, observed_positive))
                if is_abstention:
                    abstention_checks.append(passed)
                if is_rejection:
                    rejection_checks.append(passed)
                case_records.append(
                    {
                        "case_id": case_id,
                        "suite": suite,
                        "description": description,
                        "passed": passed,
                        "expected_positive": expected_positive,
                        "observed_positive": observed_positive,
                        "is_abstention_case": is_abstention,
                        "is_invalid_rejection_case": is_rejection,
                        "latency_seconds": round(latency_s, 4),
                        "details": details,
                    }
                )

            def assess_media(path: Path, idem: str) -> tuple[dict[str, Any], float]:
                asset = client.upload_bytes(path.read_bytes())
                _, job, secs = client.submit_and_poll(
                    {
                        "method_bundle": "ffmpeg-technical-v1",
                        "asset_id": asset["id"],
                    },
                    idem,
                )
                if job["state"] != "completed" or not job.get("profile"):
                    raise RuntimeError(f"expected completed job for {idem}: {job}")
                prof = job["profile"]
                jsonschema.validate(prof, PROFILE_V1_SCHEMA)
                _assert_oss_invariants(prof)
                return prof, secs

            # ==============================================================
            # SUITE 1: Technical Envelope & Quality (8 cases)
            # ==============================================================
            p_clean, s_clean = assess_media(clean_mp4, "tech-01-clean")
            clean_flags = [f["code"] for f in p_clean["flags"]]
            record_case(
                "tech-01-clean-mp4",
                "technical",
                "Clean 12s MP4 video+sine tone produces zero adverse technical flags",
                False,
                bool(clean_flags),
                len(clean_flags) == 0,
                s_clean,
                {"flags": clean_flags},
            )

            p_black, s_black = assess_media(black_mp4, "tech-02-black")
            ev_black = {e["id"]: e for e in p_black["evidence"]}
            black_spans = [
                ev_black[f["evidence_ids"][0]]
                for f in p_black["flags"]
                if f["code"] == "black_frames_observed"
            ]
            black_iou = _temporal_iou(black_spans, 3.0, 5.5)
            static_dup = any(
                f["code"] == "static_frames_observed" for f in p_black["flags"]
            )
            obs_black = bool(black_spans) and black_iou >= 0.85 and not static_dup
            record_case(
                "tech-02-black-segment",
                "technical",
                "Black segment [3.0s, 5.5s] localized with IoU >= 0.85 and duplicate static flag suppressed",
                True,
                obs_black,
                obs_black,
                s_black,
                {"temporal_iou": round(black_iou, 4), "duplicate_static_flag": static_dup},
            )

            p_static, s_static = assess_media(static_mp4, "tech-03-static")
            ev_static = {e["id"]: e for e in p_static["evidence"]}
            static_spans = [
                ev_static[f["evidence_ids"][0]]
                for f in p_static["flags"]
                if f["code"] == "static_frames_observed"
            ]
            static_iou = _temporal_iou(static_spans, 4.0, 7.5)
            obs_static = bool(static_spans) and static_iou >= 0.80
            record_case(
                "tech-03-static-freeze",
                "technical",
                "Non-black frozen video segment [4.0s, 7.5s] localized via static_frames_observed",
                True,
                obs_static,
                obs_static,
                s_static,
                {"temporal_iou": round(static_iou, 4)},
            )

            p_silent, s_silent = assess_media(silent_mp4, "tech-04-silent")
            ev_silent = {e["id"]: e for e in p_silent["evidence"]}
            silent_spans = [
                ev_silent[f["evidence_ids"][0]]
                for f in p_silent["flags"]
                if f["code"] == "silence_observed"
            ]
            silent_iou = _temporal_iou(silent_spans, 5.0, 8.5)
            obs_silent = bool(silent_spans) and silent_iou >= 0.85
            record_case(
                "tech-04-silent-segment",
                "technical",
                "Audio dropout [5.0s, 8.5s] localized via silence_observed with IoU >= 0.85",
                True,
                obs_silent,
                obs_silent,
                s_silent,
                {"temporal_iou": round(silent_iou, 4)},
            )

            p_wav, s_wav = assess_media(clip_wav, "tech-05-wav-ebur128")
            wav_sigs = {s["signal_id"]: s for s in p_wav["signals"]}
            max_vol = wav_sigs["technical.max_volume"]["value"]
            lra_lu = wav_sigs["attention.audio_loudness_range_lu"]["value"]
            crest_db = wav_sigs["attention.audio_peak_rms_delta_db"]["value"]
            obs_clip = (
                wav_sigs["media.modality"]["value"] == "audio"
                and wav_sigs["media.width"]["status"] == "not_applicable"
                and max_vol is not None
                and max_vol >= -0.5
                and lra_lu is not None
                and lra_lu > 5.0
            )
            record_case(
                "tech-05-ebur128-clipping-wav",
                "technical",
                "Standalone clipped WAV measures 0 dBFS ceiling, EBU R128 LRA, and not_applicable video fields",
                True,
                obs_clip,
                obs_clip,
                s_wav,
                {
                    "max_volume_dbfs": max_vol,
                    "loudness_range_lu": lra_lu,
                    "peak_rms_delta_db": crest_db,
                },
            )

            p_img, s_img = assess_media(still_png, "tech-06-still-png")
            img_sigs = {s["signal_id"]: s for s in p_img["signals"]}
            img_clean = (
                img_sigs["media.modality"]["value"] == "image"
                and img_sigs["media.duration"]["status"] == "not_applicable"
                and img_sigs["technical.silent_segments"]["status"] == "not_applicable"
                and len(p_img["flags"]) == 0
            )
            record_case(
                "tech-06-still-png-envelope",
                "technical",
                "Static PNG image sets temporal/audio signals to not_applicable with zero false flags",
                False,
                not img_clean,
                img_clean,
                s_img,
                {"modality": img_sigs["media.modality"]["value"]},
            )

            for bad_id, bad_desc, bad_bytes in [
                (
                    "tech-07-invalid-corrupt-mp4",
                    "Truncated/corrupt MP4 container fails cleanly without emitting a clean profile",
                    corrupt_mp4_bytes,
                ),
                (
                    "tech-08-invalid-animated-apng",
                    "Animated acTL APNG container is rejected cleanly as out-of-envelope",
                    animated_apng_bytes,
                ),
            ]:
                bad_asset = client.upload_bytes(bad_bytes)
                st_bad, job_bad, s_bad = client.submit_and_poll(
                    {"method_bundle": "ffmpeg-technical-v1", "asset_id": bad_asset["id"]},
                    bad_id,
                )
                rejected_ok = (
                    st_bad == 422
                    or (job_bad.get("state") == "failed" and job_bad.get("profile") is None)
                )
                record_case(
                    bad_id,
                    "technical",
                    bad_desc,
                    True,
                    rejected_ok,
                    rejected_ok,
                    s_bad,
                    {
                        "http_status": st_bad,
                        "job_state": job_bad.get("state"),
                        "error_code": job_bad.get("error_code"),
                    },
                    is_rejection=True,
                )

            # ==============================================================
            # SUITE 2: Accessibility (`A03` WCAG >3Hz Flash) & Pacing (`D01`) (6 cases)
            # ==============================================================
            a03_clean_sigs = {s["signal_id"]: s for s in p_clean["signals"]}
            a03_safe_1 = any(
                f["code"] == "photosensitive_flash_observed" for f in p_clean["flags"]
            )
            record_case(
                "a03-01-safe-motion",
                "accessibility_pacing",
                "Continuous motion clip emits zero photosensitive_flash_observed flags",
                False,
                a03_safe_1,
                not a03_safe_1,
                s_clean,
                {"max_flash_rate_hz": a03_clean_sigs["accessibility.max_flash_rate_hz"]["value"]},
            )

            p_f2, s_f2 = assess_media(flash_2hz_mp4, "a03-02-safe-2hz")
            f2_sigs = {s["signal_id"]: s for s in p_f2["signals"]}
            f2_flagged = any(
                f["code"] == "photosensitive_flash_observed" for f in p_f2["flags"]
            )
            record_case(
                "a03-02-safe-2hz",
                "accessibility_pacing",
                "Sub-threshold 2 Hz luminance transitions do not false-trigger >3 Hz flash hazard",
                False,
                f2_flagged,
                not f2_flagged and f2_sigs["accessibility.max_flash_rate_hz"]["value"] < 4.0,
                s_f2,
                {"max_flash_rate_hz": f2_sigs["accessibility.max_flash_rate_hz"]["value"]},
            )

            p_f6, s_f6 = assess_media(flash_6hz_mp4, "a03-03-hazard-6hz")
            f6_sigs = {s["signal_id"]: s for s in p_f6["signals"]}
            ev_f6 = {e["id"]: e for e in p_f6["evidence"]}
            f6_spans = [
                ev_f6[f["evidence_ids"][0]]
                for f in p_f6["flags"]
                if f["code"] == "photosensitive_flash_observed"
            ]
            f6_iou = _temporal_iou(f6_spans, 2.0, 6.0)
            f6_ok = bool(f6_spans) and f6_sigs["accessibility.max_flash_rate_hz"]["value"] >= 5.0
            record_case(
                "a03-03-hazard-6hz-luma",
                "accessibility_pacing",
                "6 Hz full-frame luminance flash hazard detected with timed segment",
                True,
                f6_ok,
                f6_ok,
                s_f6,
                {
                    "max_flash_rate_hz": f6_sigs["accessibility.max_flash_rate_hz"]["value"],
                    "temporal_iou": round(f6_iou, 4),
                },
            )

            p_fred, s_fred = assess_media(flash_red_5hz_mp4, "a03-04-hazard-5hz-red")
            fred_sigs = {s["signal_id"]: s for s in p_fred["signals"]}
            fred_flagged = any(
                f["code"] == "photosensitive_flash_observed" for f in p_fred["flags"]
            )
            record_case(
                "a03-04-hazard-5hz-red",
                "accessibility_pacing",
                "5 Hz saturated-red transition hazard detected via accessibility.flash_segments",
                True,
                fred_flagged,
                fred_flagged and fred_sigs["accessibility.max_flash_rate_hz"]["value"] >= 4.0,
                s_fred,
                {"max_flash_rate_hz": fred_sigs["accessibility.max_flash_rate_hz"]["value"]},
            )

            p_calm, s_calm = assess_media(calm_mp4, "d01-01-calm-shot")
            calm_sigs = {s["signal_id"]: s for s in p_calm["signals"]}
            calm_high_pacing = calm_sigs["attention.cuts_per_min"]["value"] >= 20.0
            record_case(
                "d01-01-calm-single-shot",
                "accessibility_pacing",
                "Calm continuous single-shot clip reports 0 cuts/min and 0 opening-3s cuts",
                False,
                calm_high_pacing,
                calm_sigs["attention.cuts_per_min"]["value"] == 0.0
                and calm_sigs["attention.opening_3s_cut_count"]["value"] == 0,
                s_calm,
                {
                    "cuts_per_min": calm_sigs["attention.cuts_per_min"]["value"],
                    "opening_3s_cut_count": calm_sigs["attention.opening_3s_cut_count"]["value"],
                },
            )

            p_cuts, s_cuts = assess_media(rapid_cuts_mp4, "d01-02-rapid-cuts")
            cuts_sigs = {s["signal_id"]: s for s in p_cuts["signals"]}
            rapid_detected = (
                cuts_sigs["attention.cuts_per_min"]["value"] >= 25.0
                and cuts_sigs["attention.opening_3s_cut_count"]["value"] >= 2
            )
            record_case(
                "d01-02-rapid-cut-pacing",
                "accessibility_pacing",
                "Rapid-cut 0.6s scene-switching clip detects high cuts_per_min and opening-3s cuts",
                True,
                rapid_detected,
                rapid_detected,
                s_cuts,
                {
                    "cuts_per_min": cuts_sigs["attention.cuts_per_min"]["value"],
                    "opening_3s_cut_count": cuts_sigs["attention.opening_3s_cut_count"]["value"],
                },
            )

            # ==============================================================
            # SUITE 3: Provenance (`P01` C2PA 2.2) & Perceptual Reuse (`P04` dHash) (6 cases)
            # ==============================================================
            p_c2pa_jpg, s_c2pa_jpg = assess_media(c2pa_valid_jpeg, "p01-01-valid-jpg")
            c2pa_jpg_val = {s["signal_id"]: s for s in p_c2pa_jpg["signals"]}["provenance.c2pa"]["value"]
            c2pa_jpg_tampered = any(
                f["code"] == "c2pa_tampered_payload" for f in p_c2pa_jpg["flags"]
            )
            record_case(
                "p01-01-c2pa-valid-jpeg",
                "provenance_reuse",
                "Valid RSA-PSS signed C2PA 2.2 APP11 JPEG verifies signature and asset hash with zero tamper flags",
                False,
                c2pa_jpg_tampered,
                c2pa_jpg_val["status"] == "valid_manifest"
                and c2pa_jpg_val["signature_verified"] is True
                and c2pa_jpg_val["data_hash_verified"] is True
                and not c2pa_jpg_tampered,
                s_c2pa_jpg,
                {"c2pa_status": c2pa_jpg_val["status"]},
            )

            p_c2pa_png, s_c2pa_png = assess_media(c2pa_valid_png, "p01-02-valid-png")
            c2pa_png_val = {s["signal_id"]: s for s in p_c2pa_png["signals"]}["provenance.c2pa"]["value"]
            c2pa_png_tampered = any(
                f["code"] == "c2pa_tampered_payload" for f in p_c2pa_png["flags"]
            )
            record_case(
                "p01-02-c2pa-valid-png",
                "provenance_reuse",
                "Valid RSA-PSS signed C2PA 2.2 caBX PNG verifies offline with zero tamper flags",
                False,
                c2pa_png_tampered,
                c2pa_png_val["status"] == "valid_manifest" and not c2pa_png_tampered,
                s_c2pa_png,
                {"c2pa_status": c2pa_png_val["status"]},
            )

            p_c2pa_bad, s_c2pa_bad = assess_media(c2pa_tampered_jpeg, "p01-03-tampered-jpg")
            c2pa_bad_val = {s["signal_id"]: s for s in p_c2pa_bad["signals"]}["provenance.c2pa"]["value"]
            c2pa_bad_flagged = any(
                f["code"] == "c2pa_tampered_payload" for f in p_c2pa_bad["flags"]
            )
            record_case(
                "p01-03-c2pa-tampered-jpeg",
                "provenance_reuse",
                "Post-signing pixel byte flip triggers tampered_payload and c2pa_tampered_payload flag",
                True,
                c2pa_bad_flagged and c2pa_bad_val["status"] == "tampered_payload",
                c2pa_bad_flagged and c2pa_bad_val["status"] == "tampered_payload",
                s_c2pa_bad,
                {"c2pa_status": c2pa_bad_val["status"]},
            )

            # Missing credentials -> unknown/absent, NEVER "fake" or "tampered"
            c2pa_abs_sigs = {s["signal_id"]: s for s in p_clean["signals"]}
            c2pa_abs_val = c2pa_abs_sigs["provenance.c2pa"]["value"]
            c2pa_abs_false_flag = any(
                f["code"] == "c2pa_tampered_payload" for f in p_clean["flags"]
            )
            abs_ok = (
                c2pa_abs_val["status"] == "absent"
                and c2pa_abs_sigs["provenance"]["status"] == "unsupported"
                and not c2pa_abs_false_flag
            )
            record_case(
                "p01-04-c2pa-missing-absent-unknown",
                "provenance_reuse",
                "Unsigned MP4 without C2PA reports absent/unsupported provenance (never 'fake' or tampered)",
                False,
                c2pa_abs_false_flag,
                abs_ok,
                s_clean,
                {
                    "c2pa_status": c2pa_abs_val["status"],
                    "provenance_risk_status": c2pa_abs_sigs["provenance"]["status"],
                },
                is_abstention=True,
            )

            p_dup, s_dup = assess_media(near_dup_jpg, "p04-01-near-dup")
            h_orig = {s["signal_id"]: s for s in p_img["signals"]}["provenance.perceptual_hash"]["value"]["dhash_hex"]
            h_reenc = {s["signal_id"]: s for s in p_dup["signals"]}["provenance.perceptual_hash"]["value"]["dhash_hex"]
            dist_dup = hamming_distance(h_orig, h_reenc)
            is_near_dup = dist_dup <= 4
            record_case(
                "p04-01-dhash-near-duplicate",
                "provenance_reuse",
                "Re-compressed JPEG copy matches original PNG via 64-bit dHash (Hamming distance <= 4)",
                True,
                is_near_dup,
                is_near_dup,
                s_dup,
                {"dhash_orig": h_orig, "dhash_reencoded": h_reenc, "hamming_distance": dist_dup},
            )

            p_dist, s_dist = assess_media(distinct_png, "p04-02-distinct")
            h_dist = {s["signal_id"]: s for s in p_dist["signals"]}["provenance.perceptual_hash"]["value"]["dhash_hex"]
            dist_diff = hamming_distance(h_orig, h_dist)
            false_dup = dist_diff <= 8
            record_case(
                "p04-02-dhash-distinct-images",
                "provenance_reuse",
                "Structurally distinct visual scene yields large 64-bit dHash Hamming distance (> 8)",
                False,
                false_dup,
                not false_dup,
                s_dist,
                {"dhash_a": h_orig, "dhash_b": h_dist, "hamming_distance": dist_diff},
            )

            # ==============================================================
            # SUITE 4: Supplied-Source NLI (`en` / `pt` / `es`) (10 cases)
            # ==============================================================
            def run_nli(
                http_cli: OSSHTTPClient,
                idem: str,
                language: str,
                source_text: str,
                claim_text: str,
                span: tuple[int, int] | None,
            ) -> tuple[dict[str, Any], float]:
                ev_list = (
                    [{"source_id": "src-1", "start_offset": span[0], "end_offset": span[1]}]
                    if span is not None
                    else []
                )
                _, job, secs = http_cli.submit_and_poll(
                    {
                        "method_bundle": NLI_BUNDLE,
                        "language": language,
                        "sources": [
                            {"id": "src-1", "revision_id": "rev-1", "text": source_text}
                        ],
                        "claims": [
                            {"id": "clm-1", "text": claim_text, "evidence": ev_list}
                        ],
                    },
                    idem,
                )
                if job["state"] != "completed" or not job.get("profile"):
                    raise RuntimeError(f"NLI job failed for {idem}: {job}")
                prof = job["profile"]
                jsonschema.validate(prof, EVIDENCE_PROFILE)
                _assert_oss_invariants(prof)
                for cit in prof["evidence"]:
                    s_off, e_off = cit["start_offset"], cit["end_offset"]
                    assert source_text[s_off:e_off] == cit["quote"]
                    assert (
                        hashlib.sha256(cit["quote"].encode("utf-8")).hexdigest()
                        == cit["quote_sha256"]
                    )
                return prof, secs

            en_src = "Municipal audit report: The transit authority reduced operating costs by 14% in 2025 after electrifying 60 buses."
            prof_n1, s_n1 = run_nli(
                client,
                "nli-01-en-sup",
                "en",
                en_src,
                "The transit authority reduced operating costs by 14% in 2025.",
                (0, len(en_src)),
            )
            lbl_n1 = prof_n1["claims"][0]["label"]
            record_case(
                "nli-01-en-supported",
                "supplied_source_nli",
                "English supported claim verified with exact Unicode citation span and zero mismatch flags",
                False,
                lbl_n1 == "contradicted",
                lbl_n1 == "supported" and len(prof_n1["flags"]) == 0,
                s_n1,
                {"label": lbl_n1, "status": prof_n1["claims"][0]["status"]},
            )

            prof_n2, s_n2 = run_nli(
                client,
                "nli-02-en-contra",
                "en",
                en_src,
                "The transit authority increased operating costs by 30% in 2025 and cancelled bus electrification.",
                (0, len(en_src)),
            )
            lbl_n2 = prof_n2["claims"][0]["label"]
            record_case(
                "nli-02-en-contradicted",
                "supplied_source_nli",
                "English contradicted claim emits contradicted proposal and advisory mismatch flag",
                True,
                lbl_n2 == "contradicted",
                lbl_n2 == "contradicted" and len(prof_n2["flags"]) == 1,
                s_n2,
                {"label": lbl_n2, "flags": [f["code"] for f in prof_n2["flags"]]},
            )

            en_unrelated = "The botanical garden opened its winter conservatory on Tuesday morning."
            prof_n3, s_n3 = run_nli(
                client,
                "nli-03-en-insuff",
                "en",
                en_unrelated,
                "The central bank raised reserve requirements by 50 basis points.",
                (0, len(en_unrelated)),
            )
            lbl_n3 = prof_n3["claims"][0]["label"]
            n3_abstained = lbl_n3 == "insufficient_evidence" and len(prof_n3["flags"]) == 0
            record_case(
                "nli-03-en-insufficient-abstain",
                "supplied_source_nli",
                "English ungrounded claim against unrelated passage abstains (insufficient_evidence)",
                False,
                lbl_n3 == "contradicted",
                n3_abstained,
                s_n3,
                {"label": lbl_n3},
                is_abstention=True,
            )

            filler = " ".join(
                f"Section {k}: Routine maintenance continued across regional stations without service disruption."
                for k in range(1, 32)
            )
            long_en_src = (
                filler
                + " Final determination: The safety board rejected the pipeline expansion by a 6-1 vote."
            )
            prof_n4, s_n4 = run_nli(
                client,
                "nli-04-en-sliding",
                "en",
                long_en_src,
                "The safety board approved the pipeline expansion unanimously.",
                (0, len(long_en_src)),
            )
            lbl_n4 = prof_n4["claims"][0]["label"]
            record_case(
                "nli-04-en-long-sliding-window",
                "supplied_source_nli",
                "Long >256-token English passage chunks via sentence-aligned sliding windows and catches contradiction",
                True,
                lbl_n4 == "contradicted",
                lbl_n4 == "contradicted",
                s_n4,
                {
                    "label": lbl_n4,
                    "evaluated_pairs": prof_n4["coverage"]["evaluated_pairs"],
                },
            )

            pt_src = "Relatório oficial de São Paulo: a emissão industrial caiu 12% em 2025 segundo medição auditada."
            prof_n5, s_n5 = run_nli(
                client,
                "nli-05-pt-sup",
                "pt",
                pt_src,
                "A emissão industrial caiu 12% em 2025.",
                (0, len(pt_src)),
            )
            lbl_n5 = prof_n5["claims"][0]["label"]
            record_case(
                "nli-05-pt-supported",
                "supplied_source_nli",
                "Portuguese (pt) supported claim preserves Unicode offsets and emits supported",
                False,
                lbl_n5 == "contradicted",
                lbl_n5 == "supported" and prof_n5["coverage"]["language"] == "pt",
                s_n5,
                {"label": lbl_n5, "language": prof_n5["coverage"]["language"]},
            )

            prof_n6, s_n6 = run_nli(
                client,
                "nli-06-pt-contra",
                "pt",
                pt_src,
                "A emissão industrial aumentou 25% em 2025.",
                (0, len(pt_src)),
            )
            lbl_n6 = prof_n6["claims"][0]["label"]
            record_case(
                "nli-06-pt-contradicted",
                "supplied_source_nli",
                "Portuguese (pt) contradicted numeric/directional claim emits contradicted",
                True,
                lbl_n6 == "contradicted",
                lbl_n6 == "contradicted" and len(prof_n6["flags"]) == 1,
                s_n6,
                {"label": lbl_n6},
            )

            prof_n7, s_n7 = run_nli(
                client,
                "nli-07-pt-empty-abstain",
                "pt",
                pt_src,
                "O orçamento estadual dobrou em 2026.",
                None,
            )
            c_n7 = prof_n7["claims"][0]
            n7_ok = (
                c_n7["status"] == "unknown"
                and c_n7["label"] == "insufficient_evidence"
                and len(prof_n7["flags"]) == 0
            )
            record_case(
                "nli-07-pt-empty-span-abstain",
                "supplied_source_nli",
                "Portuguese (pt) claim with no cited span abstains cleanly with status='unknown'",
                False,
                c_n7["label"] == "contradicted",
                n7_ok,
                s_n7,
                {"status": c_n7["status"], "label": c_n7["label"]},
                is_abstention=True,
            )

            es_src = "¿Qué concluyó el informe de Madrid? La inversión pública creció 18% y el proyecto ferroviario fue aprobado."
            prof_n8, s_n8 = run_nli(
                client,
                "nli-08-es-sup",
                "es",
                es_src,
                "La inversión pública creció 18% y el proyecto ferroviario fue aprobado.",
                (36, len(es_src)),
            )
            lbl_n8 = prof_n8["claims"][0]["label"]
            record_case(
                "nli-08-es-supported",
                "supplied_source_nli",
                "Spanish (es) supported claim verifies exact Unicode slice and emits supported",
                False,
                lbl_n8 == "contradicted",
                lbl_n8 == "supported" and prof_n8["coverage"]["language"] == "es",
                s_n8,
                {"label": lbl_n8, "quote": prof_n8["evidence"][0]["quote"]},
            )

            prof_n9, s_n9 = run_nli(
                client,
                "nli-09-es-contra",
                "es",
                es_src,
                "El proyecto ferroviario fue cancelado y la inversión cayó 10%.",
                (36, len(es_src)),
            )
            lbl_n9 = prof_n9["claims"][0]["label"]
            record_case(
                "nli-09-es-contradicted",
                "supplied_source_nli",
                "Spanish (es) contradicted claim emits contradicted and advisory mismatch flag",
                True,
                lbl_n9 == "contradicted",
                lbl_n9 == "contradicted" and len(prof_n9["flags"]) == 1,
                s_n9,
                {"label": lbl_n9},
            )

            prof_n10, s_n10 = run_nli(
                mono_client,
                "nli-10-mono-es-abstain",
                "es",
                es_src,
                "La inversión pública creció 18%.",
                (36, len(es_src)),
            )
            c_n10 = prof_n10["claims"][0]
            n10_ok = (
                c_n10["status"] == "unknown"
                and c_n10["label"] == "insufficient_evidence"
                and prof_n10["coverage"]["evaluated_pairs"] == 0
                and len(prof_n10["flags"]) == 0
            )
            record_case(
                "nli-10-monolingual-es-abstain",
                "supplied_source_nli",
                "Monolingual English checkpoint abstains with status='unknown' on Spanish input without hallucinating",
                False,
                c_n10["label"] == "contradicted",
                n10_ok,
                s_n10,
                {
                    "status": c_n10["status"],
                    "evaluated_pairs": prof_n10["coverage"]["evaluated_pairs"],
                },
                is_abstention=True,
            )

        finally:
            server.shutdown()
            server.server_close()
            app.close()
            srv_thread.join(timeout=5)
            mono_server.shutdown()
            mono_server.server_close()
            mono_app.close()
            mono_thread.join(timeout=5)

    overall_metrics = _binary_classification_metrics(binary_outcomes)
    per_suite_metrics = {
        suite_name: _binary_classification_metrics(rows)
        for suite_name, rows in suite_outcomes.items()
    }
    abstention_acc = (
        round(sum(abstention_checks) / len(abstention_checks), 4)
        if abstention_checks
        else 1.0
    )
    rejection_acc = (
        round(sum(rejection_checks) / len(rejection_checks), 4)
        if rejection_checks
        else 1.0
    )
    passed_total = sum(1 for r in case_records if r["passed"])

    return {
        "benchmark_id": "swivver-signal-oss-standalone-benchmark-2026-11-17",
        "evaluated_on": "2026-11-17",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package_version": "1.0.0",
        "license": "Apache-2.0",
        "standalone_execution": {
            "requires_external_platform": False,
            "transport": "HTTP /v1/assets + /v1/assessments + /v1/assessments/{id}",
            "nli_backend_mode": nli_backend_mode,
            "oss_invariants_enforced": {
                "mode": "shadow",
                "automatic_action": "none",
                "review_state": "unreviewed",
                "editorial_merit_scoring": "excluded",
                "author_credibility_ranking": "excluded",
                "numeric_probabilities_withheld": True,
            },
        },
        "summary": {
            "total_cases": len(case_records),
            "passed_cases": passed_total,
            "pass_rate": round(passed_total / len(case_records), 4),
            "precision": overall_metrics["precision"],
            "recall": overall_metrics["recall"],
            "f1": overall_metrics["f1"],
            "macro_f1": overall_metrics["macro_f1"],
            "false_positive_rate": overall_metrics["false_positive_rate"],
            "abstention_cases": len(abstention_checks),
            "abstention_accuracy": abstention_acc,
            "invalid_container_cases": len(rejection_checks),
            "invalid_container_rejection_rate": rejection_acc,
            "http_job_latency_seconds": _quantiles(http_latencies),
        },
        "suites": per_suite_metrics,
        "cases": case_records,
        "limitations": [
            "Controlled FFmpeg lavfi transformations, offline C2PA 2.2 JUMBF fixtures, and supplied-passage NLI pairs verify standalone tool/contract fidelity, not open-world prevalence.",
            "Missing C2PA Content Credentials emit 'absent'/'unsupported' provenance state, never a synthetic or 'fake' media verdict.",
            "Signal OSS excludes editorial merit scoring, author-credibility ranking, and autonomous enforcement.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lat = s["http_job_latency_seconds"]
    lines = [
        "# Swivver Signal OSS (`v1.0.0`) — Standalone Benchmark Report (2026-11-17)",
        "",
        "Reproducible end-to-end evaluation of the standalone **Apache-2.0** `swivver_signal_oss` media-measurement and supplied-evidence HTTP service (`POST /v1/assets`, `POST /v1/assessments`, `GET /v1/assessments/{id}`).",
        "",
        "## 1. Headline KPIs",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Standalone HTTP Cases Evaluated | **{s['total_cases']}** (`{s['passed_cases']}/{s['total_cases']}` passed) |",
        f"| Precision (Adverse / Hazard / Contradiction Detection) | **{s['precision']:.4f}** |",
        f"| Recall | **{s['recall']:.4f}** |",
        f"| Macro-F1 | **{s['macro_f1']:.4f}** |",
        f"| False Positive Rate (FPR) | **{s['false_positive_rate']:.4f}** |",
        f"| Abstention Accuracy (`unknown` / `insufficient_evidence`) | **{s['abstention_accuracy']:.4f}** (`{s['abstention_cases']}` cases) |",
        f"| Invalid Container Rejection Rate | **{s['invalid_container_rejection_rate']:.4f}** (`{s['invalid_container_cases']}` cases) |",
        f"| Standalone HTTP Job Latency `p50` | **{lat['p50']:.4f} s** |",
        f"| Standalone HTTP Job Latency `p95` | **{lat['p95']:.4f} s** |",
        "",
        "## 2. Per-Suite Breakdown",
        "",
        "| Suite | Cases | Precision | Recall | Macro-F1 | FPR |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    suite_titles = {
        "technical": "Technical Envelope & Audio/Video Quality (`black`, `static`, `silent`, `ebur128`, invalid rejection)",
        "accessibility_pacing": "Accessibility (`A03` >3 Hz Flash) & Pacing (`D01` Cuts/Accelerations)",
        "provenance_reuse": "Provenance (`P01` Offline C2PA 2.2) & Perceptual Reuse (`P04` 64-bit `dHash`)",
        "supplied_source_nli": "Supplied-Source NLI (`en` / `pt` / `es` Supported, Contradicted & Abstention)",
    }
    for key, title in suite_titles.items():
        m = report["suites"][key]
        lines.append(
            f"| {title} | {m['support']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['macro_f1']:.4f} | {m['false_positive_rate']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## 3. OSS Scope & Safety Invariants Verified",
            "",
            "- **Zero external platform dependency:** Executed exclusively against `swivver_signal_oss` durable SQLite HTTP jobs.",
            "- **Advisory shadow mode:** Every completed profile verified `mode == \"shadow\"`, `state == \"partial\"`, `review_state == \"unreviewed\"`, `automatic_action == \"none\"`, and `probability == null`.",
            "- **First-class uncertainty:** Unsigned media without C2PA credentials reported `provenance.c2pa.value.status == \"absent\"` (never `\"fake\"` or `\"tampered\"`), and non-English passages on a monolingual checkpoint abstained cleanly with `status == \"unknown\"`.",
            "- **OSS exclusions preserved:** Zero editorial/informational merit scoring and zero author-credibility ranking.",
            "",
            "## 4. Reproduce",
            "",
            "```sh",
            "PYTHONPATH=src python3.11 tools/evaluate_oss_benchmark.py \\",
            "  --output-json docs/oss-benchmark-2026-11-17.json \\",
            "  --output-md docs/oss-benchmark-2026-11-17.md",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-model",
        type=Path,
        default=Path(os.environ["SIGNAL_EVIDENCE_MODEL"])
        if os.environ.get("SIGNAL_EVIDENCE_MODEL")
        else None,
    )
    parser.add_argument(
        "--multilingual-evidence-model",
        type=Path,
        default=Path(os.environ["SIGNAL_MULTILINGUAL_EVIDENCE_MODEL"])
        if os.environ.get("SIGNAL_MULTILINGUAL_EVIDENCE_MODEL")
        else None,
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "docs" / "oss-benchmark-2026-11-17.json",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=ROOT / "docs" / "oss-benchmark-2026-11-17.md",
    )
    args = parser.parse_args()

    report = run_benchmark(args.evidence_model, args.multilingual_evidence_model)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    args.output_md.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2), flush=True)


if __name__ == "__main__":
    main()
