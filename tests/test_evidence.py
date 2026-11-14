import contextlib
import hashlib
import json
import os
import threading
import unittest
import time
import concurrent.futures
from pathlib import Path
from types import SimpleNamespace

import jsonschema

from swivver_signal_oss.api import EVIDENCE_PROFILE, openapi
from swivver_signal_oss.evidence import EvidenceEngine, chunk_passage
from swivver_signal_oss.media import MediaError
from swivver_signal_oss.service import Application


def request():
    return {
        "sources": [{"id": "s", "revision_id": "r", "text": "Café 🌍 source."}],
        "claims": [
            {
                "id": "c",
                "text": "Claim",
                "evidence": [{"source_id": "s", "start_offset": 0, "end_offset": 6}],
            }
        ],
    }


class Tokenizer:
    def __call__(self, a, b, **kwargs):
        if isinstance(a, str):
            return {"input_ids": list(range(len(a) + len(b)))}
        return {"count": len(a)}


class Prediction:
    def __init__(self, values):
        self.values = values

    def argmax(self, **kwargs):
        return self

    def cpu(self):
        return self

    def tolist(self):
        return self.values


class Model:
    def __init__(self, values):
        self.values = iter(values)

    def __call__(self, count):
        return SimpleNamespace(
            logits=Prediction([next(self.values) for _ in range(count)])
        )


def engine(values, max_tokens=256):
    model = object.__new__(EvidenceEngine)
    model.tokenizer = Tokenizer()
    model.model = Model(values)
    model.lock = threading.Lock()
    model.torch = SimpleNamespace(inference_mode=contextlib.nullcontext)
    model.max_tokens = max_tokens
    model.release = {"release_id": "test-only-contract"}
    model.checkpoint_sha256 = "a" * 64
    return model


class EvidenceTests(unittest.TestCase):
    def test_shared_tokenizer_is_serialized_across_workers(self):
        class BorrowedTokenizer(Tokenizer):
            borrowed = False

            def __call__(self, *args, **kwargs):
                if self.borrowed:
                    raise RuntimeError("tokenizer already borrowed")
                self.borrowed = True
                try:
                    time.sleep(0.001)
                    return super().__call__(*args, **kwargs)
                finally:
                    self.borrowed = False

        model = engine([0] * 16)
        model.tokenizer = BorrowedTokenizer()
        normalized = EvidenceEngine.validate(**request())
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            profiles = list(
                pool.map(
                    lambda index: model.evaluate(normalized, str(index), "b" * 64),
                    range(16),
                )
            )
        self.assertEqual(len(profiles), 16)
        self.assertTrue(
            all(p["claims"][0]["label"] == "contradicted" for p in profiles)
        )

    def test_immutable_contract_artifacts(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(
            EVIDENCE_PROFILE,
            json.loads((root / "schemas/evidence-profile-0.1.schema.json").read_text()),
        )
        self.assertEqual(
            openapi(),
            json.loads((root / "schemas/standalone.openapi.json").read_text()),
        )
        jsonschema.Draft202012Validator.check_schema(EVIDENCE_PROFILE)

    def test_unicode_citations_proposals_and_no_numeric_confidence(self):
        normalized = EvidenceEngine.validate(**request())
        for prediction, label in enumerate(
            ["contradicted", "supported", "insufficient_evidence"]
        ):
            profile = engine([prediction]).evaluate(normalized, "job", "b" * 64)
            jsonschema.validate(profile, EVIDENCE_PROFILE)
            self.assertEqual(profile["claims"][0]["label"], label)
            self.assertEqual(profile["evidence"][0]["quote"], "Café 🌍")
            self.assertEqual(
                profile["evidence"][0]["quote_sha256"],
                hashlib.sha256("Café 🌍".encode()).hexdigest(),
            )
            self.assertIsNone(profile["claims"][0]["confidence"]["probability"])
            self.assertEqual(bool(profile["flags"]), prediction == 0)

    def test_conflicting_passages_and_missing_or_over_budget_abstain(self):
        data = request()
        data["claims"][0]["evidence"] *= 2
        normalized = EvidenceEngine.validate(**data)
        profile = engine([0, 1]).evaluate(normalized, "job", "b" * 64)
        self.assertEqual(profile["claims"][0]["label"], "mixed")
        profile = engine([], max_tokens=2).evaluate(normalized, "job", "b" * 64)
        self.assertEqual(profile["claims"][0]["status"], "unknown")
        self.assertEqual(profile["flags"], [])
        self.assertEqual(profile["coverage"]["claims_with_over_budget_passages"], 1)
        data["claims"][0]["evidence"] = []
        profile = engine([]).evaluate(EvidenceEngine.validate(**data), "job", "b" * 64)
        self.assertEqual(profile["claims"][0]["label"], "insufficient_evidence")

    def test_untrusted_inputs_do_not_resolve_or_rewrite_passages(self):
        for section, field, value in [
            ("sources", "sha256", "a" * 64),
            ("sources", "text", ""),
            ("sources", "text", "x" * 64001),
            ("sources", "id", ""),
            ("sources", "url", 32),
            ("sources", "unexpected", True),
            ("claims", "id", ""),
            ("claims", "text", ""),
            ("claims", "text", "x" * 4001),
            ("claims", "evidence", "not-list"),
            ("claims", "unexpected", True),
        ]:
            data = request()
            data[section][0][field] = value
            with self.subTest(section=section, field=field), self.assertRaises(
                MediaError
            ):
                EvidenceEngine.validate(**data)
        for field, value in [
            ("source_id", "unknown"),
            ("start_offset", True),
            ("start_offset", -1),
            ("end_offset", 100),
        ]:
            data = request()
            data["claims"][0]["evidence"][0][field] = value
            with self.subTest(field=field), self.assertRaises(MediaError):
                EvidenceEngine.validate(**data)
        for section in ("claims", "sources"):
            for value in ([], None, "invalid"):
                data = request()
                data[section] = value
                with self.assertRaises(MediaError):
                    EvidenceEngine.validate(**data)
            data = request()
            data[section] *= 2
            with self.assertRaises(MediaError):
                EvidenceEngine.validate(**data)

    @unittest.skipUnless(
        os.getenv("SIGNAL_TEST_EVIDENCE_MODEL"), "optional actual local checkpoint test"
    )
    def test_installed_model_and_output_contract(self):
        model = EvidenceEngine(Path(os.environ["SIGNAL_TEST_EVIDENCE_MODEL"]))
        profile = model.evaluate(EvidenceEngine.validate(**request()), "job", "b" * 64)
        jsonschema.validate(profile, EVIDENCE_PROFILE)
        self.assertEqual(profile["model"]["checkpoint_sha256"], model.checkpoint_sha256)

    def test_long_passage_sliding_window_chunking_unicode_offsets_and_aggregation(self):
        class SoftmaxPrediction:
            def __init__(self, prob_rows):
                self.prob_rows = prob_rows

            def argmax(self, **kwargs):
                indices = [
                    max(range(3), key=lambda k: row[k]) for row in self.prob_rows
                ]
                return Prediction(indices)

            def softmax(self, **kwargs):
                return Prediction(self.prob_rows)

        class SoftmaxModel:
            def __init__(self, prob_rows):
                self.prob_rows = iter(prob_rows)

            def __call__(self, count):
                return SimpleNamespace(
                    logits=SoftmaxPrediction(
                        [next(self.prob_rows) for _ in range(count)]
                    )
                )

        prefix = "Introdução 🌍: contextual header.\n\n"
        sentences = [
            "Dr. Müller noted baseline transit operations across Café corridors in 2024.",
            "Preliminary rider surveys showed routine seasonal fluctuation during winter.",
            "Municipal budget appendices listed capital maintenance schedules for bridges.",
            "Audited figures confirm bus ridership rose by 18% across all metropolitan lines!",
            "Regional freight rail schedules remained unchanged throughout the third quarter.",
            "Final appendices archive station-level turnstile counts for public inspection.",
        ]
        body = " ".join(sentences)
        full_source = prefix + body + "\nRodapé."
        span_start = len(prefix)
        span_end = span_start + len(body)
        claim_text = "Bus ridership rose 18%."
        tok = Tokenizer()
        max_tokens = 185

        windows = chunk_passage(
            full_source, span_start, span_end, claim_text, tok, max_tokens
        )
        self.assertIsNotNone(windows)
        self.assertGreaterEqual(len(windows), 3)

        # Every window fits max_tokens and slices exact Unicode code points
        for idx, (w_start, w_end) in enumerate(windows):
            self.assertGreaterEqual(w_start, span_start)
            self.assertLessEqual(w_end, span_end)
            self.assertLess(w_start, w_end)
            win_quote = full_source[w_start:w_end]
            self.assertLessEqual(
                len(tok(win_quote, claim_text, truncation=False)["input_ids"]),
                max_tokens,
            )
            if idx > 0:
                prev_start, prev_end = windows[idx - 1]
                self.assertGreater(w_start, prev_start)
                # Adjacent sentence windows overlap (prev_end > w_start)
                self.assertGreater(prev_end, w_start)

        # Softmax score aggregation: two overlapping windows entail (0.72 vs 0.96), rest neutral
        prob_rows = []
        peak_window = None
        seen_entail = 0
        for w_start, w_end in windows:
            win_quote = full_source[w_start:w_end]
            if "rose by 18%" in win_quote:
                seen_entail += 1
                if seen_entail == 1:
                    prob_rows.append([0.05, 0.72, 0.23])
                else:
                    prob_rows.append([0.02, 0.96, 0.02])
                    peak_window = (w_start, w_end)
            else:
                prob_rows.append([0.03, 0.04, 0.93])
        self.assertGreaterEqual(seen_entail, 2)

        nli = engine([], max_tokens=max_tokens)
        nli.model = SoftmaxModel(prob_rows)
        normalized = EvidenceEngine.validate(
            claims=[
                {
                    "id": "c-long",
                    "text": claim_text,
                    "evidence": [
                        {
                            "source_id": "s1",
                            "start_offset": span_start,
                            "end_offset": span_end,
                        }
                    ],
                }
            ],
            sources=[{"id": "s1", "revision_id": "rev1", "text": full_source}],
            language="en",
        )
        profile = nli.evaluate(normalized, "job-long", "c" * 64)
        jsonschema.validate(profile, EVIDENCE_PROFILE)
        self.assertEqual(profile["claims"][0]["label"], "supported")
        self.assertEqual(profile["claims"][0]["status"], "proposed")
        self.assertEqual(profile["coverage"]["evaluated_pairs"], len(windows))
        self.assertEqual(profile["coverage"]["claims_with_over_budget_passages"], 0)
        self.assertEqual(len(profile["evidence"]), 1)
        cited = profile["evidence"][0]
        self.assertEqual(
            (cited["start_offset"], cited["end_offset"]),
            peak_window,
        )
        self.assertEqual(
            full_source[cited["start_offset"] : cited["end_offset"]],
            cited["quote"],
        )
        self.assertIn("rose by 18%", cited["quote"])

        # Intra-passage mixed windows (one window entails, later window contradicts)
        mixed_probs = [[0.03, 0.92, 0.05]] + [
            [0.02, 0.03, 0.95] for _ in range(len(windows) - 2)
        ] + [[0.94, 0.03, 0.03]]
        nli_mixed = engine([], max_tokens=max_tokens)
        nli_mixed.model = SoftmaxModel(mixed_probs)
        mixed_profile = nli_mixed.evaluate(normalized, "job-mixed", "d" * 64)
        jsonschema.validate(mixed_profile, EVIDENCE_PROFILE)
        self.assertEqual(mixed_profile["claims"][0]["label"], "mixed")
        self.assertEqual(len(mixed_profile["evidence"]), 2)
        self.assertEqual(len(mixed_profile["flags"]), 1)
        self.assertEqual(mixed_profile["flags"][0]["automatic_action"], "none")

        # Oversized single unpunctuated run falls back to word/code-point windows cleanly
        unpunctuated = " ".join(f"palavra_{i}_é" for i in range(40))
        word_windows = chunk_passage(
            unpunctuated, 0, len(unpunctuated), "Claim", tok, 60
        )
        self.assertIsNotNone(word_windows)
        self.assertGreater(len(word_windows), 2)
        for ws, we in word_windows:
            self.assertLessEqual(
                len(tok(unpunctuated[ws:we], "Claim", truncation=False)["input_ids"]),
                60,
            )

    def test_multilingual_en_pt_es_routing_and_monolingual_abstention(self):
        import tempfile

        pt_source = "Relatório oficial de São Paulo: a emissão caiu 12% em 2025."
        es_source = "¿Qué concluyó la investigación en Madrid? La emisión bajó 12% en el año."

        mono = engine([1])
        mono.languages = ("en",)
        mono.release = {"release_id": "en-deberta-test", "languages": ["en"]}

        # Monolingual checkpoint abstains cleanly with explicit reason on pt and es
        for lang, src_text, claim_txt in [
            ("pt", pt_source, "A emissão caiu 12%."),
            ("es", es_source, "La emisión bajó 12%."),
        ]:
            norm = EvidenceEngine.validate(
                claims=[
                    {
                        "id": f"c-{lang}",
                        "text": claim_txt,
                        "evidence": [
                            {
                                "source_id": "s",
                                "start_offset": 0,
                                "end_offset": len(src_text),
                            }
                        ],
                    }
                ],
                sources=[{"id": "s", "revision_id": "r1", "text": src_text}],
                language=lang,
            )
            abstained = mono.evaluate(norm, f"job-{lang}", "e" * 64)
            jsonschema.validate(abstained, EVIDENCE_PROFILE)
            self.assertEqual(abstained["claims"][0]["status"], "unknown")
            self.assertEqual(abstained["claims"][0]["label"], "insufficient_evidence")
            self.assertEqual(abstained["evidence"], [])
            self.assertEqual(abstained["flags"], [])
            self.assertEqual(abstained["coverage"]["evaluated_pairs"], 0)
            self.assertEqual(abstained["coverage"]["language"], lang)
            self.assertIn(
                "en-deberta-test", abstained["claims"][0]["limitations"][0]
            )

        # Attach multilingual NLI engine supporting en, pt, es via Application
        multi = engine([1, 0])
        multi.languages = ("en", "pt", "es")
        multi.release = {
            "release_id": "mdeberta-xnli-test",
            "languages": ["en", "pt", "es"],
        }
        multi.checkpoint_sha256 = "f" * 64

        with tempfile.TemporaryDirectory() as tmp:
            app = Application(Path(tmp), workers=1)
            app.install_evidence_engine(mono, multilingual_engine=multi)
            self.assertEqual(mono.supported_languages(), ("en", "pt", "es"))

            pt_req = {
                "method_bundle": "source-evidence-nli-v1",
                "language": "pt",
                "claims": [
                    {
                        "id": "c-pt",
                        "text": "A emissão caiu 12%.",
                        "evidence": [
                            {
                                "source_id": "s",
                                "start_offset": 32,
                                "end_offset": len(pt_source),
                            }
                        ],
                    }
                ],
                "sources": [{"id": "s", "revision_id": "r1", "text": pt_source}],
            }
            es_req = {
                "method_bundle": "source-evidence-nli-v1",
                "language": "es",
                "claims": [
                    {
                        "id": "c-es",
                        "text": "La emisión subió 30%.",
                        "evidence": [
                            {
                                "source_id": "s",
                                "start_offset": 42,
                                "end_offset": len(es_source),
                            }
                        ],
                    }
                ],
                "sources": [{"id": "s", "revision_id": "r1", "text": es_source}],
            }

            norm_pt = app.normalize("owner", pt_req)
            prof_pt = mono.evaluate(norm_pt, "ref-pt", "1" * 64)
            jsonschema.validate(prof_pt, EVIDENCE_PROFILE)
            self.assertEqual(prof_pt["claims"][0]["label"], "supported")
            self.assertEqual(prof_pt["coverage"]["language"], "pt")
            self.assertEqual(prof_pt["model"]["release_id"], "mdeberta-xnli-test")
            self.assertEqual(
                prof_pt["evidence"][0]["quote"], pt_source[32 : len(pt_source)]
            )

            norm_es = app.normalize("owner", es_req)
            prof_es = mono.evaluate(norm_es, "ref-es", "2" * 64)
            jsonschema.validate(prof_es, EVIDENCE_PROFILE)
            self.assertEqual(prof_es["claims"][0]["label"], "contradicted")
            self.assertEqual(prof_es["coverage"]["language"], "es")
            self.assertEqual(len(prof_es["flags"]), 1)
            self.assertEqual(prof_es["flags"][0]["automatic_action"], "none")
            self.assertEqual(
                prof_es["evidence"][0]["quote"], es_source[42 : len(es_source)]
            )

            # Unsupported language 'fr' rejected at normalization
            bad_req = dict(pt_req, language="fr")
            with self.assertRaises(MediaError):
                app.normalize("owner", bad_req)


if __name__ == "__main__":
    unittest.main()
