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
SUPPORTED_LANGUAGES = ("en", "pt", "es")
LANGUAGE_NAMES = {
    "en": "English",
    "pt": "Portuguese",
    "es": "Spanish",
}
_ABBREVIATIONS = frozenset(
    {
        "dr",
        "mr",
        "ms",
        "mrs",
        "sr",
        "sra",
        "srta",
        "prof",
        "st",
        "vs",
        "etc",
        "art",
        "no",
        "fig",
        "inc",
        "ltd",
        "jr",
        "av",
        "pág",
        "pag",
    }
)


def _split_line_sentences(
    passage: str,
    l_start: int,
    l_end: int,
    base_offset: int,
    out: list[tuple[int, int]],
) -> None:
    if l_start >= l_end:
        return
    segment = passage[l_start:l_end]
    cur = 0
    for match in re.finditer(r"([.!?…]+)[\"')\]»”]*(?=\s+)", segment):
        punct = match.group(1)
        if punct == ".":
            prefix = segment[cur : match.start()]
            prev_word = re.search(r"([^\W\d_]+)$", prefix, re.UNICODE)
            if prev_word:
                word = prev_word.group(1)
                if word.lower() in _ABBREVIATIONS or (
                    len(word) == 1 and word.isupper()
                ):
                    continue
        rs = cur
        re_ = match.end()
        while rs < re_ and segment[rs].isspace():
            rs += 1
        while re_ > rs and segment[re_ - 1].isspace():
            re_ -= 1
        if rs < re_:
            out.append((base_offset + l_start + rs, base_offset + l_start + re_))
        cur = match.end()
    rs = cur
    re_ = len(segment)
    while rs < re_ and segment[rs].isspace():
        rs += 1
    while re_ > rs and segment[re_ - 1].isspace():
        re_ -= 1
    if rs < re_:
        out.append((base_offset + l_start + rs, base_offset + l_start + re_))


def segment_sentences(
    source_text: str, start_offset: int, end_offset: int
) -> list[tuple[int, int]]:
    """Segment source_text[start_offset:end_offset] into sentence spans with exact Unicode offsets."""
    passage = source_text[start_offset:end_offset]
    units: list[tuple[int, int]] = []
    pos = 0
    for break_match in re.finditer(r"\n+", passage):
        _split_line_sentences(
            passage, pos, break_match.start(), start_offset, units
        )
        pos = break_match.end()
    _split_line_sentences(passage, pos, len(passage), start_offset, units)
    return units or [(start_offset, end_offset)]


def _split_codepoint_span(
    source_text: str,
    u_start: int,
    u_end: int,
    tok_count,
    max_tokens: int,
) -> list[tuple[int, int]] | None:
    chunks: list[tuple[int, int]] = []
    cur = u_start
    while cur < u_end:
        if tok_count(cur, cur + 1) > max_tokens:
            return None
        if tok_count(cur, u_end) <= max_tokens:
            chunks.append((cur, u_end))
            break
        lo = cur + 1
        hi = u_end
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if tok_count(cur, mid) <= max_tokens:
                lo = mid
            else:
                hi = mid - 1
        while lo > cur + 1 and tok_count(cur, lo) > max_tokens:
            lo -= 1
        chunks.append((cur, lo))
        width = lo - cur
        overlap = max(1, width // 4) if width >= 4 else 0
        next_cur = lo - overlap
        if next_cur <= cur:
            next_cur = lo
        cur = next_cur
    return chunks


def chunk_passage(
    source_text: str,
    start_offset: int,
    end_offset: int,
    claim_text: str,
    tokenizer,
    max_tokens: int,
) -> list[tuple[int, int]] | None:
    """Split a source passage into sentence-aligned overlapping windows <= max_tokens.

    Returns a list of exact (win_start, win_end) Unicode code-point offsets into
    source_text, or None if even a single-character window + claim exceeds max_tokens.
    """
    cache: dict[tuple[int, int], int] = {}

    def tok_count(a: int, b: int) -> int:
        key = (a, b)
        if key not in cache:
            cache[key] = len(
                tokenizer(source_text[a:b], claim_text, truncation=False)["input_ids"]
            )
        return cache[key]

    if tok_count(start_offset, end_offset) <= max_tokens:
        return [(start_offset, end_offset)]

    raw_sentences = segment_sentences(source_text, start_offset, end_offset)
    units: list[tuple[int, int]] = []
    for s_start, s_end in raw_sentences:
        if tok_count(s_start, s_end) <= max_tokens:
            units.append((s_start, s_end))
            continue
        sub_text = source_text[s_start:s_end]
        words = [
            (s_start + m.start(), s_start + m.end())
            for m in re.finditer(r"\S+", sub_text)
        ]
        if not words:
            sub_chunks = _split_codepoint_span(
                source_text, s_start, s_end, tok_count, max_tokens
            )
            if sub_chunks is None:
                return None
            units.extend(sub_chunks)
            continue
        for w_start, w_end in words:
            if tok_count(w_start, w_end) <= max_tokens:
                units.append((w_start, w_end))
            else:
                sub_chunks = _split_codepoint_span(
                    source_text, w_start, w_end, tok_count, max_tokens
                )
                if sub_chunks is None:
                    return None
                units.extend(sub_chunks)

    if not units:
        return None

    n = len(units)
    windows: list[tuple[int, int]] = []
    i = 0
    while i < n:
        step = 1
        lo = i
        hi = i
        while hi + step < n:
            cand = hi + step
            if tok_count(units[i][0], units[cand][1]) <= max_tokens:
                lo = cand
                hi = cand
                step *= 2
            else:
                hi = cand
                break
        else:
            if hi < n - 1 and tok_count(units[i][0], units[n - 1][1]) <= max_tokens:
                lo = n - 1
                hi = n - 1
            else:
                hi = n - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if tok_count(units[i][0], units[mid][1]) <= max_tokens:
                lo = mid
            else:
                hi = mid - 1
        j = lo
        while j > i and tok_count(units[i][0], units[j][1]) > max_tokens:
            j -= 1
        windows.append((units[i][0], units[j][1]))
        if j >= n - 1:
            break
        count = j - i + 1
        overlap = max(1, count // 3) if count >= 2 else 0
        next_i = j + 1 - overlap
        while (
            next_i <= j
            and tok_count(units[next_i][0], units[j + 1][1]) > max_tokens
        ):
            next_i += 1
        i = next_i

    return windows


def _extract_batch_scores(logits) -> list[tuple[int, tuple[float, float, float]]]:
    preds = logits.argmax(dim=1).cpu().tolist()
    if hasattr(logits, "softmax"):
        probs = logits.softmax(dim=-1).cpu().tolist()
        return [
            (int(p), (float(row[0]), float(row[1]), float(row[2])))
            for p, row in zip(preds, probs)
        ]
    out: list[tuple[int, tuple[float, float, float]]] = []
    for p in preds:
        idx = int(p)
        row = [0.0, 0.0, 0.0]
        row[idx] = 1.0
        out.append((idx, (row[0], row[1], row[2])))
    return out


class EvidenceEngine:
    def __init__(
        self,
        directory: Path,
        *,
        threads=4,
        multilingual_directory: Path | None = None,
    ):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        directory = directory.resolve(strict=True)
        self.release = json.loads((directory / "release.json").read_text())
        if self.release["method_bundle"] != BUNDLE:
            raise ValueError("unsupported model release")
        raw_langs = self.release.get("languages", ["en"])
        if (
            not isinstance(raw_langs, list)
            or not raw_langs
            or any(
                not isinstance(lang, str) or lang not in SUPPORTED_LANGUAGES
                for lang in raw_langs
            )
        ):
            raise ValueError("unsupported model language declaration")
        self.languages = tuple(dict.fromkeys(raw_langs))
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
        self.multilingual_engine = (
            EvidenceEngine(multilingual_directory, threads=threads)
            if multilingual_directory is not None
            else None
        )

    def supported_languages(self) -> tuple[str, ...]:
        own = list(getattr(self, "languages", ("en",)))
        multi = getattr(self, "multilingual_engine", None)
        if multi is not None:
            for lang in multi.supported_languages():
                if lang not in own:
                    own.append(lang)
        return tuple(own)

    @staticmethod
    def validate(claims, sources, *, language: str | None = None):
        if language is not None and language not in SUPPORTED_LANGUAGES:
            raise MediaError("unsupported evidence language")
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
        out = {"claims": output, "sources": normalized}
        if language is not None:
            out["language"] = language
        return out

    def evaluate(self, request, reference, input_hash):
        language = request.get("language", "en")
        if language not in SUPPORTED_LANGUAGES:
            raise MediaError("unsupported evidence language")
        own_languages = tuple(getattr(self, "languages", ("en",)))
        if language not in own_languages:
            multi = getattr(self, "multilingual_engine", None)
            if multi is not None and language in multi.supported_languages():
                return multi.evaluate(request, reference, input_hash)
            with self.lock:
                return self._abstain_unsupported_language(
                    request, reference, input_hash, language, own_languages
                )
        # Fast-tokenizer calls can mutate padding/truncation state even during
        # budget inspection. Serialize the entire shared tokenizer/model path.
        with self.lock:
            return self._evaluate(request, reference, input_hash, language)

    def _abstain_unsupported_language(
        self,
        request,
        reference: str,
        input_hash: str,
        language: str,
        own_languages: tuple[str, ...],
    ):
        started = time.perf_counter()
        lang_label = LANGUAGE_NAMES[language]
        supported_str = ", ".join(own_languages)
        reason = (
            f"Installed NLI checkpoint ({self.release['release_id']}) supports "
            f"[{supported_str}] only and cannot evaluate {lang_label} ('{language}') "
            "passages; abstaining cleanly without a multilingual checkpoint."
        )
        results = [
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
                "limitations": [reason],
            }
            for claim in request["claims"]
        ]
        return {
            "schema_version": "signal-evidence-profile/0.1",
            "method_bundle": BUNDLE,
            "mode": "shadow",
            "state": "partial",
            "review_state": "unreviewed",
            "subject": {"snapshot_id": reference, "input_sha256": input_hash},
            "claims": results,
            "evidence": [],
            "flags": [],
            "model": {
                "release_id": self.release["release_id"],
                "checkpoint_sha256": self.checkpoint_sha256,
                "max_tokens": self.max_tokens,
            },
            "coverage": {
                "provided_claims": len(results),
                "evaluated_pairs": 0,
                "claims_with_over_budget_passages": 0,
                "retrieval": "not_performed",
                "language": language,
                "editorial_quality": "unsupported",
                "author_credibility": "unsupported",
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "runtime_seconds": round(time.perf_counter() - started, 6),
        }

    def _evaluate(self, request, reference, input_hash, language: str = "en"):
        started = time.perf_counter()
        sources = {s["id"]: s for s in request["sources"]}
        pairs: list[tuple[str, str]] = []
        # Map claim_id -> list of (source_dict, list of (win_start, win_end, pair_idx))
        claim_spans: dict[str, list[tuple[dict, list[tuple[int, int, int]]]]] = {
            c["id"]: [] for c in request["claims"]
        }
        skipped: set[str] = set()
        chunked_claims: set[str] = set()

        for claim in request["claims"]:
            for span in claim["evidence"]:
                source = sources[span["source_id"]]
                windows = chunk_passage(
                    source["text"],
                    span["start_offset"],
                    span["end_offset"],
                    claim["text"],
                    self.tokenizer,
                    self.max_tokens,
                )
                if windows is None:
                    skipped.add(claim["id"])
                    continue
                if len(windows) > 1:
                    chunked_claims.add(claim["id"])
                win_records: list[tuple[int, int, int]] = []
                for w_start, w_end in windows:
                    w_text = source["text"][w_start:w_end]
                    pair_idx = len(pairs)
                    pairs.append((w_text, claim["text"]))
                    win_records.append((w_start, w_end, pair_idx))
                claim_spans[claim["id"]].append((source, win_records))

        scored_pairs: list[tuple[int, tuple[float, float, float]]] = []
        with self.torch.inference_mode():
            for start in range(0, len(pairs), 16):
                chunk = pairs[start : start + 16]
                features = self.tokenizer(
                    [p[0] for p in chunk],
                    [p[1] for p in chunk],
                    padding=True,
                    return_tensors="pt",
                )
                scored_pairs.extend(
                    _extract_batch_scores(self.model(**features).logits)
                )

        citations: list[dict] = []
        results = []
        flags = []
        lang_name = LANGUAGE_NAMES[language]

        def add_citation(source: dict, w_start: int, w_end: int) -> str:
            quote = source["text"][w_start:w_end]
            citation_id = f"e{len(citations) + 1}"
            citations.append(
                {
                    "id": citation_id,
                    "source_id": source["id"],
                    "revision_id": source["revision_id"],
                    "source_sha256": source["sha256"],
                    "start_offset": w_start,
                    "end_offset": w_end,
                    "quote": quote,
                    "quote_sha256": hashlib.sha256(quote.encode()).hexdigest(),
                }
            )
            return citation_id

        for claim in request["claims"]:
            spans_for_claim = claim_spans[claim["id"]]
            observed_labels: set[str] = set()
            ids: list[str] = []

            for source, win_records in spans_for_claim:
                if len(win_records) == 1:
                    w_start, w_end, p_idx = win_records[0]
                    pred_idx, _ = scored_pairs[p_idx]
                    observed_labels.add(LABELS[pred_idx])
                    ids.append(add_citation(source, w_start, w_end))
                else:
                    # Aggregate window-level entailment/contradiction scores across overlapping windows
                    contra_wins = []
                    entail_wins = []
                    for w_start, w_end, p_idx in win_records:
                        pred_idx, (p_c, p_e, _p_n) = scored_pairs[p_idx]
                        win_label = LABELS[pred_idx]
                        if win_label == "contradicted":
                            contra_wins.append((p_c, -w_start, w_start, w_end))
                        elif win_label == "supported":
                            entail_wins.append((p_e, -w_start, w_start, w_end))

                    selected_windows: list[tuple[int, int]] = []
                    if contra_wins and entail_wins:
                        observed_labels.add("contradicted")
                        observed_labels.add("supported")
                        best_c = max(contra_wins)
                        best_e = max(entail_wins)
                        selected_windows = sorted(
                            {(best_c[2], best_c[3]), (best_e[2], best_e[3])}
                        )
                    elif contra_wins:
                        observed_labels.add("contradicted")
                        best_c = max(contra_wins)
                        selected_windows = [(best_c[2], best_c[3])]
                    elif entail_wins:
                        observed_labels.add("supported")
                        best_e = max(entail_wins)
                        selected_windows = [(best_e[2], best_e[3])]
                    else:
                        observed_labels.add("insufficient_evidence")
                        # Select window with highest max(p_contra, p_entail), tie-breaking earliest
                        best_n = max(
                            (
                                max(scored_pairs[p_idx][1][0], scored_pairs[p_idx][1][1]),
                                -w_start,
                                w_start,
                                w_end,
                            )
                            for w_start, w_end, p_idx in win_records
                        )
                        selected_windows = [(best_n[2], best_n[3])]

                    for w_start, w_end in selected_windows:
                        ids.append(add_citation(source, w_start, w_end))

            if not spans_for_claim or claim["id"] in skipped:
                label = "insufficient_evidence"
                status = "unknown"
            elif "supported" in observed_labels and "contradicted" in observed_labels:
                label = "mixed"
                status = "proposed"
            elif "contradicted" in observed_labels:
                label = "contradicted"
                status = "proposed"
            elif "supported" in observed_labels:
                label = "supported"
                status = "proposed"
            else:
                label = "insufficient_evidence"
                status = "proposed"

            limitations = [
                f"Provided {lang_name} evidence only; source-relative proposal, not verified real-world truth."
            ]
            if claim["id"] in chunked_claims:
                limitations.append(
                    "Long source passage evaluated across sentence-aligned sliding windows within model token budget."
                )
            if claim["id"] in skipped:
                limitations.append(
                    "At least one selected passage exceeds the model token budget."
                )

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
                    "limitations": limitations,
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
                "language": language,
                "editorial_quality": "unsupported",
                "author_credibility": "unsupported",
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "runtime_seconds": round(time.perf_counter() - started, 6),
        }
