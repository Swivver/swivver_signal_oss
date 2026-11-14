"""Full-decode technical observations. Thresholds describe detectors, not policy."""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

METHOD_BUNDLE = "ffmpeg-technical-v1"
THRESHOLDS = {
    "black_min_seconds": 0.5,
    "black_pixel_threshold": 0.05,
    "black_picture_ratio": 0.98,
    "static_min_seconds": 2.0,
    "static_noise_db": -60,
    "static_flag_black_overlap_ratio": 0.95,
    "silence_min_seconds": 0.5,
    "silence_threshold_db": -50,
}
UNSUPPORTED = {
    "safety": "No semantic safety detector has been validated in this release.",
    "age_suitability": "No age-suitability assessment is implemented.",
    "synthetic_media": "No forensic or watermark detector is implemented.",
    "identity": "No consented reference or identity verification is available.",
    "advertising_integrity": "No sponsorship or offer assessment is implemented.",
    "claim_support": "No versioned source passages are available to this engine.",
    "rights": "Similarity and metadata cannot establish permission.",
    "provenance": "C2PA validation is not implemented in this release.",
    "caption_completeness": "Embedded tracks do not establish burned-in caption presence or accuracy.",
    "attention_design": "No attention or flash-safety assessment is implemented.",
}


class MediaError(ValueError):
    """An input cannot be measured within the declared processing scope."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MediaError(
            "media tool unavailable or processing deadline exceeded"
        ) from exc
    if result.returncode:
        # Tool diagnostics may contain private paths or attacker-controlled tags.
        raise MediaError("media decode failed")
    return result


def probe(path: Path) -> dict:
    result = _run(
        [
            "ffprobe",
            "-v",
            "error",
            "-protocol_whitelist",
            "file,pipe",
            "-format_whitelist",
            "mov,matroska,webm",
            "-show_streams",
            "-show_format",
            "-of",
            "json",
            str(path),
        ],
        timeout=20,
    )
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MediaError("invalid media metadata") from exc


def intervals(log: str, start_key: str, end_key: str, duration: float) -> list[dict]:
    """Recover bounded playback-relative intervals, including events at EOF."""
    number = r"(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)"
    pattern = re.compile(
        rf"(?:{re.escape(start_key)}\s*:\s*{number})|(?:{re.escape(end_key)}\s*:\s*{number})"
    )
    pending = None
    found = []
    for match in pattern.finditer(log):
        if match.group(1) is not None:
            pending = max(0.0, min(float(match.group(1)), duration))
        elif pending is not None:
            end = max(pending, min(float(match.group(2)), duration))
            if end > pending:
                found.append(
                    {"start_seconds": round(pending, 6), "end_seconds": round(end, 6)}
                )
            pending = None
    if pending is not None and pending < duration:
        found.append(
            {"start_seconds": round(pending, 6), "end_seconds": round(duration, 6)}
        )
    return found


def _volume(log: str, name: str) -> float | None:
    match = re.search(rf"{name}:\s*(-?inf|-?\d+(?:\.\d+)?)\s*dB", log)
    if match:
        value = float(match.group(1))
        return value if math.isfinite(value) else None
    return None


def analyze(
    path: Path,
    *,
    snapshot_id: str = "local",
    input_sha256: str | None = None,
    expected_sha256: str | None = None,
    expected_size_bytes: int | None = None,
) -> dict:
    started = time.perf_counter()
    path = path.resolve(strict=True)
    size = path.stat().st_size
    if size <= 0 or size > 512 * 1024 * 1024:
        raise MediaError("media size must be between 1 byte and 512 MiB")
    digest = sha256_file(path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise MediaError("media checksum mismatch")
    if expected_size_bytes is not None and size != expected_size_bytes:
        raise MediaError("media size mismatch")
    metadata = probe(path)
    streams = metadata.get("streams", [])
    video = [
        s
        for s in streams
        if s.get("codec_type") == "video"
        and not s.get("disposition", {}).get("attached_pic")
    ]
    audio = [s for s in streams if s.get("codec_type") == "audio"]
    if len(video) != 1 or len(audio) > 1:
        raise MediaError(
            "this release supports one video track and at most one audio track"
        )
    try:
        duration = float(metadata["format"]["duration"])
    except (KeyError, ValueError, TypeError) as exc:
        raise MediaError("finite media duration is required") from exc
    if not math.isfinite(duration) or not 10 <= duration <= 200.1:
        raise MediaError("media duration must be 10–200 seconds")
    v = video[0]
    if "duration" in v and abs(float(v["duration"]) - duration) > 0.2:
        raise MediaError("video track does not cover the container timeline")
    if not 0 < v.get("width", 0) <= 4096 or not 0 < v.get("height", 0) <= 4096:
        raise MediaError("video dimensions exceed processing scope")
    command = [
        "ffmpeg",
        "-hide_banner",
        "-nostdin",
        "-v",
        "info",
        "-xerror",
        "-threads",
        "2",
        "-protocol_whitelist",
        "file,pipe",
        "-format_whitelist",
        "mov,matroska,webm",
        "-i",
        str(path),
        "-t",
        "201",
        "-map",
        f"0:{v['index']}",
        "-filter_threads",
        "1",
        "-vf",
        "blackdetect=d=0.5:pix_th=0.05:pic_th=0.98,freezedetect=n=-60dB:d=2",
    ]
    if audio:
        command.extend(
            [
                "-map",
                f"0:{audio[0]['index']}",
                "-af",
                "silencedetect=n=-50dB:d=0.5,volumedetect",
            ]
        )
    command.extend(["-threads", "2", "-f", "null", "-"])
    decoded = _run(command)
    log = decoded.stderr.decode("utf-8", errors="replace")
    evidence = []
    signals = []
    flags = []

    def measurement(
        signal_id, value, unit, *, status="measured", limitation=None, evidence_ids=None
    ):
        signals.append(
            {
                "signal_id": signal_id,
                "kind": "measurement",
                "status": status,
                "value": value,
                "unit_or_scale": unit,
                "method_id": METHOD_BUNDLE,
                "confidence": {
                    "status": "not_applicable",
                    "probability": None,
                    "calibration_id": None,
                },
                "evidence_ids": evidence_ids or [],
                "limitations": [limitation] if limitation else [],
            }
        )

    measurement(
        "media.duration",
        round(duration, 6),
        "seconds",
        limitation="Container duration; endpoint tolerance 0.1 seconds.",
    )
    measurement("media.width", v["width"], "pixels")
    measurement("media.height", v["height"], "pixels")
    measurement("media.audio_track_count", len(audio), "tracks")
    measurement(
        "accessibility.embedded_caption_track_count",
        sum(s.get("codec_type") == "subtitle" for s in streams),
        "tracks",
        limitation=UNSUPPORTED["caption_completeness"],
    )
    categories = [
        (
            "technical.black_segments",
            "black_start",
            "black_end",
            "black_frames_observed",
        ),
        (
            "technical.static_segments",
            "freeze_start",
            "freeze_end",
            "static_frames_observed",
        ),
    ]
    if audio:
        categories.append(
            (
                "technical.silent_segments",
                "silence_start",
                "silence_end",
                "silence_observed",
            )
        )
    for signal_id, start, end, flag_code in categories:
        spans = intervals(log, start, end, duration)
        ids = []
        for span in spans:
            evidence_id = f"e{len(evidence) + 1}"
            ids.append(evidence_id)
            evidence.append(
                {
                    "id": evidence_id,
                    "media_sha256": digest,
                    "modality": "audio" if "silent" in signal_id else "video",
                    **span,
                }
            )
            # Black video is also static by definition. Keep the raw static
            # measurement/citation, but avoid a duplicate review warning when
            # black detection already explains at least 95% of this interval.
            explained_by_black = signal_id == "technical.static_segments" and any(
                max(
                    0,
                    min(span["end_seconds"], black["end_seconds"])
                    - max(span["start_seconds"], black["start_seconds"]),
                )
                / (span["end_seconds"] - span["start_seconds"])
                >= THRESHOLDS["static_flag_black_overlap_ratio"]
                for black in intervals(log, "black_start", "black_end", duration)
            )
            if explained_by_black:
                continue
            flags.append(
                {
                    "code": flag_code,
                    "signal_id": signal_id,
                    "evidence_ids": [evidence_id],
                    "review_state": "unreviewed",
                    "automatic_action": "none",
                    "interpretation": "Observable pattern; intent, harm and editorial appropriateness are not inferred.",
                }
            )
        measurement(
            signal_id,
            len(spans),
            "segments",
            evidence_ids=ids,
            limitation="Thresholded full-decode observation; deliberate black screens, still images and silence may be appropriate.",
        )
    if not audio:
        measurement(
            "technical.silent_segments",
            None,
            "segments",
            status="not_applicable",
            limitation="No audio stream.",
        )
    for name in ("mean_volume", "max_volume"):
        measurement(
            f"technical.{name}",
            _volume(log, name) if audio else None,
            "dBFS",
            status="measured" if audio else "not_applicable",
            limitation="First audio track; null denotes no audio or a non-finite value for digital silence. Not a speech intelligibility measure.",
        )
    for signal_id, reason in UNSUPPORTED.items():
        signals.append(
            {
                "signal_id": signal_id,
                "kind": "risk",
                "status": "unsupported",
                "value": None,
                "unit_or_scale": None,
                "method_id": None,
                "evidence_ids": [],
                "confidence": {
                    "status": "uncalibrated",
                    "probability": None,
                    "calibration_id": None,
                },
                "limitations": [reason],
            }
        )
    version = _run(["ffmpeg", "-version"], timeout=5).stdout.decode().splitlines()[0]
    return {
        "schema_version": "signal-profile/0.1",
        "method_bundle": METHOD_BUNDLE,
        "subject": {
            "snapshot_id": snapshot_id,
            "input_sha256": input_sha256 or digest,
            "media_sha256": digest,
        },
        "state": "partial",
        "mode": "shadow",
        "review_state": "unreviewed",
        "signals": signals,
        "evidence": evidence,
        "flags": flags,
        "coverage": {
            "technical_decode": "full",
            "semantic_video": "unsupported",
            "speech_recognition": "unsupported",
            "ocr": "unsupported",
            "source_passages": "not_ingested",
        },
        "thresholds": THRESHOLDS,
        "tools": {"ffmpeg": version, "signal": "0.2.0"},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_seconds": round(time.perf_counter() - started, 6),
    }
