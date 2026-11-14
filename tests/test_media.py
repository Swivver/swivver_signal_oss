import json
import subprocess
import tempfile
import unittest
import jsonschema
from pathlib import Path
from unittest.mock import patch

from swivver_signal_oss.media import (
    MediaError,
    analyze,
    intervals,
    probe,
    sha256_file,
    _run,
    _volume,
)
from swivver_signal_oss.server import download, NoRedirect


class IntervalTests(unittest.TestCase):
    def test_playback_bounds_and_eof(self):
        log = "silence_start: -0.02 silence_end: 2 silence_start: 8 silence_end: 14 silence_start: 9"
        self.assertEqual(
            intervals(log, "silence_start", "silence_end", 10),
            [
                {"start_seconds": 0, "end_seconds": 2},
                {"start_seconds": 8, "end_seconds": 10},
                {"start_seconds": 9, "end_seconds": 10},
            ],
        )
        self.assertEqual(
            intervals(
                "silence_end: 3 silence_start: 7 silence_end: 7",
                "silence_start",
                "silence_end",
                10,
            ),
            [],
        )
        self.assertEqual(
            intervals(
                "black_start: 1e-2 black_end: 1.5", "black_start", "black_end", 10
            ),
            [{"start_seconds": 0.01, "end_seconds": 1.5}],
        )

    def test_nonfinite_audio(self):
        self.assertIsNone(_volume("max_volume: -inf dB", "max_volume"))
        self.assertIsNone(_volume("", "mean_volume"))
        self.assertEqual(_volume("mean_volume: -23.7 dB", "mean_volume"), -23.7)

    def test_decode_failures_are_errors(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("ffmpeg", 1)):
            with patch("subprocess.run", side_effect=error), self.assertRaises(
                MediaError
            ):
                _run(["ffmpeg"])
        with patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, b"", b"private path"),
        ):
            with self.assertRaisesRegex(MediaError, "decode failed"):
                _run(["ffmpeg"])
        with patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, b"not JSON", b""),
        ):
            with self.assertRaises(MediaError):
                probe(Path("input.mp4"))


class MediaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.video = cls.directory / "observations.mp4"
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=160x90:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=16000",
                "-t",
                "12",
                "-vf",
                "drawbox=x=0:y=0:w=iw:h=ih:color=black:t=fill:enable='gte(t,3)*lt(t,5)'",
                "-af",
                "volume=0:enable='gte(t,6)*lt(t,8)'",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(cls.video),
            ],
            check=True,
            capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_localized_observations_do_not_become_semantic_verdicts(self):
        result = analyze(
            self.video,
            snapshot_id="snapshot",
            input_sha256="b" * 64,
            expected_sha256=sha256_file(self.video),
        )
        self.assertEqual(result["subject"]["input_sha256"], "b" * 64)
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["mode"], "shadow")
        self.assertFalse(
            any(f["code"] == "static_frames_observed" for f in result["flags"])
        )
        self.assertGreaterEqual(
            next(
                s["value"]
                for s in result["signals"]
                if s["signal_id"] == "technical.static_segments"
            ),
            1,
        )
        evidence = {e["id"]: e for e in result["evidence"]}
        for code, start, end in [
            ("black_frames_observed", 3, 5),
            ("silence_observed", 6, 8),
        ]:
            spans = [
                evidence[f["evidence_ids"][0]]
                for f in result["flags"]
                if f["code"] == code
            ]
            self.assertTrue(
                any(
                    abs(e["start_seconds"] - start) < 0.15
                    and abs(e["end_seconds"] - end) < 0.15
                    for e in spans
                )
            )
        self.assertTrue(
            all(s["confidence"]["probability"] is None for s in result["signals"])
        )
        self.assertEqual(
            next(s["status"] for s in result["signals"] if s["signal_id"] == "safety"),
            "unsupported",
        )
        self.assertTrue(all(f["automatic_action"] == "none" for f in result["flags"]))
        json.dumps(result, allow_nan=False)
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/profile-0.1.schema.json").read_text()
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(result, schema)

    def test_byte_binding_and_processing_scope(self):
        with self.assertRaisesRegex(MediaError, "checksum"):
            analyze(self.video, expected_sha256="0" * 64)
        with self.assertRaisesRegex(MediaError, "size mismatch"):
            analyze(self.video, expected_size_bytes=1)
        empty = self.directory / "empty.mp4"
        empty.touch()
        with self.assertRaises(MediaError):
            analyze(empty)
        base = {
            "streams": [
                {
                    "codec_type": "video",
                    "index": 0,
                    "width": 160,
                    "height": 90,
                    "duration": "12",
                }
            ],
            "format": {"duration": "12"},
        }
        cases = [
            {},
            {"streams": [], "format": {"duration": "12"}},
            {"streams": base["streams"], "format": {}},
            {"streams": base["streams"], "format": {"duration": "nan"}},
            {"streams": base["streams"], "format": {"duration": "9"}},
            {
                "streams": [dict(base["streams"][0], width=8000)],
                "format": {"duration": "12"},
            },
            {
                "streams": [dict(base["streams"][0], duration="4")],
                "format": {"duration": "12"},
            },
        ]
        for metadata in cases:
            with self.subTest(metadata=metadata), patch(
                "swivver_signal_oss.media.probe", return_value=metadata
            ), self.assertRaises(MediaError):
                analyze(self.video)

    def test_no_audio_is_not_silence_or_missing_captions(self):
        path = self.directory / "no-audio.mp4"
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-y",
                "-i",
                str(self.video),
                "-an",
                "-c:v",
                "copy",
                str(path),
            ],
            check=True,
            capture_output=True,
        )
        result = analyze(path)
        signals = {s["signal_id"]: s for s in result["signals"]}
        self.assertEqual(
            signals["technical.silent_segments"]["status"], "not_applicable"
        )
        self.assertIsNone(signals["technical.max_volume"]["value"])
        self.assertEqual(signals["caption_completeness"]["status"], "unsupported")
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/profile-0.1.schema.json").read_text()
        )
        jsonschema.validate(result, schema)


class OriginTests(unittest.TestCase):
    def test_closed_egress_and_redirects(self):
        for url in [
            "file:///etc/passwd",
            "http://localhost:9000/media",
            "https://media.example:443@evil.example/a",
            "https://media.example:443/a#fragment",
            "https://user:password@media.example:443/a",
        ]:
            with self.subTest(url=url), self.assertRaises(MediaError):
                download(url, Path("/unused"), {"media.example:443"}, 100)
        self.assertIsNone(
            NoRedirect().redirect_request(
                None, None, 302, "", {}, "http://localhost/secret"
            )
        )


if __name__ == "__main__":
    unittest.main()
