"""Source-relative NLI proposals with exact, hash-bound passage citations.

This module does not retrieve the web, evaluate editorial merit, rank authors,
or approve a factual claim for publication. Numerical confidence is withheld.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .media import MediaError, sha256_file

BUNDLE = "source-evidence-nli-v1"
LABELS = ["contradicted", "supported", "insufficient_evidence"]


class EvidenceEngine:
    def __init__(self, directory: Path, *, threads=4):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        directory = directory.resolve(strict=True)
        self.release = json.loads((directory / "release.json").read_text())
        if self.release["method_bundle"] != BUNDLE:
            raise ValueError("unsupported model release")
        torch.set_num_threads(threads)
        self.tokenizer = AutoTokenizer.from_pretrained(
            directory, local_files_only=True, trust_remote_code=False
        )
        self.model = AutoModelForSequenceClassification.from_pretrained(
            directory,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
        self.model.eval()
        self.torch = torch
        self.lock = threading.Lock()
        self.max_tokens = int(self.release["max_tokens"])
        self.checkpoint_sha256 = sha256_file(directory / "model.safetensors")
        expected = self.release.get("checkpoint_sha256")
        if (
            not isinstance(expected, str)
            or not re.fullmatch("[a-f0-9]{64}", expected)
            or expected != self.checkpoint_sha256
        ):
            raise ValueError("model checksum mismatch")
        if [self.model.config.id2label[i].lower() for i in range(3)] != [
            "contradiction",
            "entailment",
            "neutral",
        ]:
            raise ValueError("model label mapping mismatch")

    @staticmethod
    def validate(claims, sources):
        if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
            raise MediaError("provide 1–20 stored source passages")
        source_map = {}
        normalized = []
        for source in sources:
            if not isinstance(source, dict) or set(source) - {
                "id",
                "revision_id",
                "text",
                "sha256",
                "url",
                "retrieved_at",
            }:
                raise MediaError("invalid source")
            if not all(
                isinstance(source.get(k), str) and 0 < len(source[k]) <= 200
                for k in ("id", "revision_id")
            ):
                raise MediaError("source identity required")
            if source["id"] in source_map:
                raise MediaError("duplicate source")
            text = source.get("text")
            if not isinstance(text, str) or not 0 < len(text) <= 64000:
                raise MediaError("invalid source text")
            digest = hashlib.sha256(text.encode()).hexdigest()
            if source.get("sha256", digest) != digest:
                raise MediaError("source checksum mismatch")
            item = {k: source[k] for k in ("id", "revision_id", "text")}
            item["sha256"] = digest
            for k in ("url", "retrieved_at"):
                if k in source:
                    if not isinstance(source[k], str) or len(source[k]) > 4096:
                        raise MediaError("invalid source metadata")
                    item[k] = source[k]
            source_map[item["id"]] = item
            normalized.append(item)
        if sum(len(s["text"]) for s in normalized) > 400000:
            raise MediaError("source budget exceeded")
        if not isinstance(claims, list) or not 1 <= len(claims) <= 20:
            raise MediaError("provide 1–20 claims")
        seen = set()
        output = []
        for claim in claims:
            if not isinstance(claim, dict) or set(claim) - {"id", "text", "evidence"}:
                raise MediaError("invalid claim")
            if (
                not isinstance(claim.get("id"), str)
                or not 0 < len(claim["id"]) <= 100
                or claim["id"] in seen
            ):
                raise MediaError("unique claim identity required")
            seen.add(claim["id"])
            if (
                not isinstance(claim.get("text"), str)
                or not 0 < len(claim["text"]) <= 4000
            ):
                raise MediaError("invalid claim text")
            spans = claim.get("evidence", [])
            if not isinstance(spans, list) or len(spans) > 20:
                raise MediaError("invalid claim evidence")
            references = []
            for span in spans:
                if not isinstance(span, dict) or set(span) != {
                    "source_id",
                    "start_offset",
                    "end_offset",
                }:
                    raise MediaError("invalid evidence locator")
                source = source_map.get(span["source_id"])
                if source is None:
                    raise MediaError("unknown source reference")
                start, end = span["start_offset"], span["end_offset"]
                if (
                    not isinstance(start, int)
                    or isinstance(start, bool)
                    or not isinstance(end, int)
                    or isinstance(end, bool)
                    or not 0 <= start < end <= len(source["text"])
                ):
                    raise MediaError("evidence span outside source")
                references.append(span)
            output.append(
                {"id": claim["id"], "text": claim["text"], "evidence": references}
            )
        return {"claims": output, "sources": normalized}

    def evaluate(self, request, reference, input_hash):
        # Fast-tokenizer calls can mutate padding/truncation state even during
        # budget inspection. Serialize the entire shared tokenizer/model path.
        with self.lock:
            return self._evaluate(request, reference, input_hash)

    def _evaluate(self, request, reference, input_hash):
        started = time.perf_counter()
        sources = {s["id"]: s for s in request["sources"]}
        pairs = []
        citations = []
        mapping = {c["id"]: [] for c in request["claims"]}
        skipped = set()
        for claim in request["claims"]:
            for span in claim["evidence"]:
                source = sources[span["source_id"]]
                text = source["text"][span["start_offset"] : span["end_offset"]]
                tokenized = self.tokenizer(text, claim["text"], truncation=False)
                if len(tokenized["input_ids"]) > self.max_tokens:
                    skipped.add(claim["id"])
                    continue
                citation_id = f"e{len(citations)+1}"
                citations.append(
                    {
                        "id": citation_id,
                        "source_id": source["id"],
                        "revision_id": source["revision_id"],
                        "source_sha256": source["sha256"],
                        "start_offset": span["start_offset"],
                        "end_offset": span["end_offset"],
                        "quote": text,
                        "quote_sha256": hashlib.sha256(text.encode()).hexdigest(),
                    }
                )
                mapping[claim["id"]].append(len(pairs))
                pairs.append((text, claim["text"]))
        predictions = []
        with self.torch.inference_mode():
            for start in range(0, len(pairs), 16):
                chunk = pairs[start : start + 16]
                features = self.tokenizer(
                    [p[0] for p in chunk],
                    [p[1] for p in chunk],
                    padding=True,
                    return_tensors="pt",
                )
                predictions.extend(
                    self.model(**features).logits.argmax(dim=1).cpu().tolist()
                )
        results = []
        flags = []
        for claim in request["claims"]:
            indices = mapping[claim["id"]]
            labels = {LABELS[predictions[i]] for i in indices}
            if not indices or claim["id"] in skipped:
                label = "insufficient_evidence"
                status = "unknown"
            elif "supported" in labels and "contradicted" in labels:
                label = "mixed"
                status = "proposed"
            elif "contradicted" in labels:
                label = "contradicted"
                status = "proposed"
            elif "supported" in labels:
                label = "supported"
                status = "proposed"
            else:
                label = "insufficient_evidence"
                status = "proposed"
            ids = [citations[i]["id"] for i in indices]
            results.append(
                {
                    "claim_id": claim["id"],
                    "label": label,
                    "status": status,
                    "evidence_ids": ids,
                    "confidence": {
                        "status": "uncalibrated",
                        "probability": None,
                        "calibration_id": None,
                    },
                    "limitations": [
                        "Provided English evidence only; source-relative proposal, not verified real-world truth."
                    ]
                    + (
                        [
                            "At least one selected passage exceeds the model token budget."
                        ]
                        if claim["id"] in skipped
                        else []
                    ),
                }
            )
            if status == "proposed" and label in ("contradicted", "mixed"):
                flags.append(
                    {
                        "code": "claim_evidence_mismatch_proposed",
                        "claim_id": claim["id"],
                        "evidence_ids": ids,
                        "automatic_action": "none",
                        "review_state": "unreviewed",
                    }
                )
        return {
            "schema_version": "signal-evidence-profile/0.1",
            "method_bundle": BUNDLE,
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
                "evaluated_pairs": len(pairs),
                "claims_with_over_budget_passages": len(skipped),
                "retrieval": "not_performed",
                "language": "en",
                "editorial_quality": "unsupported",
                "author_credibility": "unsupported",
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "runtime_seconds": round(time.perf_counter() - started, 6),
        }
