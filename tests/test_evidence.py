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
from swivver_signal_oss.evidence import EvidenceEngine
from swivver_signal_oss.media import MediaError


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


if __name__ == "__main__":
    unittest.main()
