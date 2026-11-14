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

    def test_video_600s_ceiling_and_caller_bounds(self):
        long_video = self.directory / "long-210s.mp4"
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-f",
                "lavfi",
                "-i",
                "color=c=navy:s=64x36:r=5",
                "-t",
                "210",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-pix_fmt",
                "yuv420p",
                str(long_video),
            ],
            check=True,
            capture_output=True,
        )
        result = analyze(long_video)
        signals = {s["signal_id"]: s for s in result["signals"]}
        self.assertEqual(signals["media.modality"]["value"], "video")
        self.assertAlmostEqual(signals["media.duration"]["value"], 210.0, delta=0.2)
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/profile-0.1.schema.json").read_text()
        )
        jsonschema.validate(result, schema)

        with self.assertRaisesRegex(MediaError, "duration"):
            analyze(long_video, max_duration_seconds=200.0)
        with patch(
            "swivver_signal_oss.media.probe",
            return_value={
                "streams": [
                    {
                        "codec_type": "video",
                        "index": 0,
                        "width": 160,
                        "height": 90,
                        "duration": "605",
                    }
                ],
                "format": {"format_name": "mov,mp4,m4a,3gp", "duration": "605"},
            },
        ), self.assertRaisesRegex(MediaError, "duration"):
            analyze(self.video)

    def test_standalone_audio_formats_and_not_applicable_video_metrics(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/profile-0.1.schema.json").read_text()
        )
        specs = [
            ("clip.mp3", []),
            ("clip.wav", []),
            ("clip.flac", []),
            ("clip.m4a", ["-c:a", "aac"]),
            ("clip.ogg", ["-ac", "2", "-c:a", "vorbis", "-strict", "-2"]),
            ("clip.aac", ["-c:a", "aac", "-f", "adts"]),
        ]
        for filename, extra_args in specs:
            with self.subTest(audio_format=filename):
                target = self.directory / filename
                subprocess.run(
                    [
                        "ffmpeg",
                        "-v",
                        "error",
                        "-nostdin",
                        "-f",
                        "lavfi",
                        "-i",
                        "sine=frequency=440:sample_rate=16000",
                        "-t",
                        "2",
                        *extra_args,
                        str(target),
                    ],
                    check=True,
                    capture_output=True,
                )
                profile = analyze(target)
                jsonschema.validate(profile, schema)
                by_id = {s["signal_id"]: s for s in profile["signals"]}
                self.assertEqual(by_id["media.modality"]["value"], "audio")
                self.assertEqual(by_id["media.duration"]["status"], "measured")
                self.assertEqual(by_id["media.audio_track_count"]["value"], 1)
                self.assertEqual(by_id["technical.mean_volume"]["status"], "measured")
                for na_id in (
                    "media.width",
                    "media.height",
                    "media.aspect_ratio",
                    "technical.black_segments",
                    "technical.static_segments",
                    "accessibility.flash_segments",
                ):
                    self.assertEqual(by_id[na_id]["status"], "not_applicable")
                    self.assertIsNone(by_id[na_id]["value"])

        too_short = self.directory / "short.wav"
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=16000",
                "-t",
                "0.4",
                str(too_short),
            ],
            check=True,
            capture_output=True,
        )
        with self.assertRaisesRegex(MediaError, "audio duration"):
            analyze(too_short)

    def test_standalone_still_images_exif_and_gps_omission(self):
        import struct
        import zlib

        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/profile-0.1.schema.json").read_text()
        )
        jpg = self.directory / "still.jpg"
        png = self.directory / "still.png"
        webp = self.directory / "still.webp"
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x180:rate=1",
                "-frames:v",
                "1",
                str(jpg),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=200x100:rate=1",
                "-frames:v",
                "1",
                str(png),
            ],
            check=True,
            capture_output=True,
        )
        webp.write_bytes(
            bytes.fromhex(
                "524946461a000000574542505650384c0d0000002f00000010071011118888fe0700"
            )
        )

        # Inject a TIFF/EXIF APP1 segment into JPEG with Make + Orientation + GPS IFD (0x8825)
        make_str = b"SwivverCam\x00\x00"
        ifd_entries = (
            struct.pack("<HHI4s", 0x010F, 2, 11, struct.pack("<I", 8 + 2 + 36 + 4))
            + struct.pack("<HHII", 0x0112, 3, 1, 6)
            + struct.pack("<HHII", 0x8825, 4, 1, 8 + 2 + 36 + 4 + len(make_str))
        )
        gps_ifd = struct.pack("<H", 1) + struct.pack("<HHII", 0x0002, 2, 4, 0x4E000000) + b"\x00\x00\x00\x00"
        tiff = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 3) + ifd_entries + b"\x00\x00\x00\x00" + make_str + gps_ifd
        app1_payload = b"Exif\x00\x00" + tiff
        raw_jpg = jpg.read_bytes()
        jpg_exif = self.directory / "still-exif.jpg"
        jpg_exif.write_bytes(
            raw_jpg[:2]
            + b"\xff\xe1"
            + struct.pack(">H", 2 + len(app1_payload))
            + app1_payload
            + raw_jpg[2:]
        )

        for img_path, expected_ratio in [
            (jpg_exif, round(320 / 180, 6)),
            (png, 2.0),
            (webp, 1.0),
        ]:
            with self.subTest(image=img_path.name):
                profile = analyze(img_path)
                jsonschema.validate(profile, schema)
                by_id = {s["signal_id"]: s for s in profile["signals"]}
                self.assertEqual(by_id["media.modality"]["value"], "image")
                self.assertEqual(by_id["media.aspect_ratio"]["value"], expected_ratio)
                for na_id in (
                    "media.duration",
                    "media.audio_track_count",
                    "technical.black_segments",
                    "technical.static_segments",
                    "technical.silent_segments",
                    "accessibility.flash_segments",
                ):
                    self.assertEqual(by_id[na_id]["status"], "not_applicable")
                    self.assertIsNone(by_id[na_id]["value"])
                if img_path == jpg_exif:
                    exif_val = by_id["media.exif"]["value"]
                    self.assertTrue(exif_val["present"])
                    self.assertEqual(exif_val["fields"]["make"], "SwivverCam")
                    self.assertEqual(exif_val["fields"]["orientation"], 6)
                    self.assertNotIn("gps", str(exif_val).lower())

        # Animated PNG (acTL chunk) must be rejected
        def png_chunk(ctype: bytes, body: bytes) -> bytes:
            crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
            return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)

        raw_png = png.read_bytes()
        apng = self.directory / "anim.png"
        apng.write_bytes(raw_png[:33] + png_chunk(b"acTL", b"\x00" * 8) + raw_png[33:])
        with self.assertRaisesRegex(MediaError, "animated PNG"):
            analyze(apng)

    def test_photosensitive_flash_screening_synthetic_and_real_fixtures(self):
        calm = self.directory / "synth-2hz.mp4"
        flashing = self.directory / "synth-6hz.mp4"
        for target, expr in [
            (calm, "lt(mod(t\\,0.5)\\,0.25)"),
            (flashing, "gte(t\\,2)*lt(t\\,5)*lt(mod(t\\,0.166667)\\,0.083333)"),
        ]:
            subprocess.run(
                [
                    "ffmpeg",
                    "-v",
                    "error",
                    "-nostdin",
                    "-f",
                    "lavfi",
                    "-i",
                    "color=c=black:s=160x90:r=25",
                    "-t",
                    "10",
                    "-vf",
                    f"drawbox=x=0:y=0:w=iw:h=ih:color=white:t=fill:enable='{expr}'",
                    "-c:v",
                    "libx264",
                    "-pix_fmt",
                    "yuv420p",
                    str(target),
                ],
                check=True,
                capture_output=True,
            )

        calm_res = analyze(calm)
        calm_signals = {s["signal_id"]: s for s in calm_res["signals"]}
        self.assertEqual(calm_signals["accessibility.flash_segments"]["value"], 0)
        self.assertFalse(
            any(f["code"] == "photosensitive_flash_observed" for f in calm_res["flags"])
        )

        flash_res = analyze(flashing)
        flash_signals = {s["signal_id"]: s for s in flash_res["signals"]}
        self.assertGreaterEqual(flash_signals["accessibility.flash_segments"]["value"], 1)
        self.assertGreaterEqual(flash_signals["accessibility.max_flash_rate_hz"]["value"], 4.0)
        flash_flags = [
            f for f in flash_res["flags"] if f["code"] == "photosensitive_flash_observed"
        ]
        self.assertTrue(flash_flags)
        self.assertTrue(all(f["automatic_action"] == "none" for f in flash_flags))

        real_dir = (
            Path(__file__).resolve().parents[2] / "swivver_signal/data/analysis-v03"
        )
        if real_dir.is_dir():
            for hz, expected_flag in [
                (0, False),
                (2, False),
                (3, False),
                (5, True),
                (8, True),
            ]:
                fixture = real_dir / f"flash-{hz}hz.mp4"
                if fixture.exists():
                    prof = analyze(fixture)
                    observed = any(
                        f["code"] == "photosensitive_flash_observed"
                        for f in prof["flags"]
                    )
                    self.assertEqual(observed, expected_flag, f"flash-{hz}hz mismatch")


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
