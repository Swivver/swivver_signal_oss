"""Full-decode technical observations. Thresholds describe detectors, not policy."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .c2pa import METHOD_ID as C2PA_METHOD_ID, inspect_c2pa

METHOD_BUNDLE = "ffmpeg-technical-v1"
FORMAT_WHITELIST = (
    "mov,mp4,m4a,3gp,matroska,webm,"
    "mp3,wav,flac,ogg,aac,"
    "image2,jpeg_pipe,png_pipe,webp_pipe"
)
VIDEO_FORMATS = {"mov", "mp4", "m4a", "3gp", "matroska", "webm"}
AUDIO_FORMATS = {"mp3", "wav", "flac", "mov", "mp4", "m4a", "3gp", "ogg", "aac", "matroska", "webm"}
IMAGE_FORMATS = {"image2", "jpeg_pipe", "png_pipe", "webp_pipe"}
IMAGE_CODECS = {"mjpeg", "png", "webp"}

THRESHOLDS = {
    "black_min_seconds": 0.5,
    "black_pixel_threshold": 0.05,
    "black_picture_ratio": 0.98,
    "static_min_seconds": 2.0,
    "static_noise_db": -60,
    "static_flag_black_overlap_ratio": 0.95,
    "silence_min_seconds": 0.5,
    "silence_threshold_db": -50,
    "flash_min_hz": 4.0,
    "flash_luma_delta": 0.10,
    "flash_red_ratio": 0.80,
    "flash_red_delta": 0.20,
    "video_min_seconds": 10.0,
    "audio_min_seconds": 1.0,
    "max_duration_seconds": 600.0,
}
UNSUPPORTED = {
    "safety": "No semantic safety detector has been validated in this release.",
    "age_suitability": "No age-suitability assessment is implemented.",
    "synthetic_media": "No forensic or watermark detector is implemented.",
    "identity": "No consented reference or identity verification is available.",
    "advertising_integrity": "No sponsorship or offer assessment is implemented.",
    "claim_support": "No versioned source passages are available to this engine.",
    "rights": "Similarity and metadata cannot establish permission.",
    "provenance": "Offline JUMBF inspection (provenance.c2pa) does not establish CA trust-list validity, OCSP status, or authorship.",
    "caption_completeness": "Embedded tracks do not establish burned-in caption presence or accuracy.",
    "attention_design": "Manipulative engagement intent and clinical audience effects are not inferred.",
}

_EXIF_SAFE_TAGS = {
    0x010F: "make",
    0x0110: "model",
    0x0112: "orientation",
    0x0131: "software",
    0x0132: "datetime",
    0x9003: "datetime_original",
    0xA001: "color_space",
}
_TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


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
            FORMAT_WHITELIST,
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


def _detect_still_image_magic(path: Path) -> str | None:
    """Inspect magic bytes for JPEG/PNG/WebP still images and reject animated variants."""
    with path.open("rb") as stream:
        head = stream.read(64)
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        data = path.read_bytes()
        pos = 8
        while pos + 12 <= len(data):
            length = struct.unpack(">I", data[pos : pos + 4])[0]
            ctype = data[pos + 4 : pos + 8]
            if ctype == b"acTL":
                raise MediaError("animated PNG is outside single-image scope")
            if ctype in (b"IDAT", b"IEND"):
                break
            pos += 12 + length
        return "png"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        if len(head) >= 21 and head[12:16] == b"VP8X" and (head[20] & 0x02):
            raise MediaError("animated WebP is outside single-image scope")
        return "webp"
    return None


def _parse_tiff_exif(tiff: bytes) -> dict:
    if len(tiff) < 8 or tiff[:4] not in (b"II*\x00", b"MM\x00*"):
        return {"present": False, "tag_count": 0, "fields": {}}
    endian = "<" if tiff[:2] == b"II" else ">"
    first_ifd = struct.unpack(endian + "I", tiff[4:8])[0]
    fields: dict[str, str | int] = {}
    tag_count = 0
    visited: set[int] = set()
    queue = [first_ifd]

    while queue and len(visited) < 4:
        offset = queue.pop(0)
        if offset in visited or offset + 2 > len(tiff):
            continue
        visited.add(offset)
        num_entries = struct.unpack(endian + "H", tiff[offset : offset + 2])[0]
        if num_entries > 512:
            break
        cursor = offset + 2
        for _ in range(num_entries):
            if cursor + 12 > len(tiff):
                break
            tag, dtype, count, raw_val = struct.unpack(
                endian + "HHII", tiff[cursor : cursor + 12]
            )
            cursor += 12
            if tag == 0x8825:  # Explicitly skip GPS IFD to avoid geolocation PII leakage.
                continue
            if tag == 0x8769:  # ExifSubIFD pointer
                queue.append(raw_val)
                continue
            tag_count += 1
            field_name = _EXIF_SAFE_TAGS.get(tag)
            if field_name is None or count > 256:
                continue
            unit_size = _TIFF_TYPE_SIZES.get(dtype)
            if unit_size is None:
                continue
            byte_len = unit_size * count
            if byte_len <= 4:
                val_bytes = tiff[cursor - 4 : cursor - 4 + byte_len]
            else:
                if raw_val + byte_len > len(tiff):
                    continue
                val_bytes = tiff[raw_val : raw_val + byte_len]
            if dtype == 2:  # ASCII
                text = val_bytes.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
                if text:
                    fields[field_name] = text[:120]
            elif dtype == 3 and count == 1 and len(val_bytes) == 2:  # SHORT
                fields[field_name] = struct.unpack(endian + "H", val_bytes)[0]
            elif dtype == 4 and count == 1 and len(val_bytes) == 4:  # LONG
                fields[field_name] = struct.unpack(endian + "I", val_bytes)[0]
    return {"present": tag_count > 0, "tag_count": tag_count, "fields": fields}


def extract_exif(path: Path) -> dict:
    """Extract sanitized technical EXIF summary (omitting GPS tags) from JPEG/PNG/WebP."""
    data = path.read_bytes()
    if data.startswith(b"\xff\xd8"):
        pos = 2
        while pos + 4 <= len(data) and data[pos] == 0xFF:
            while pos < len(data) and data[pos] == 0xFF:
                pos += 1
            if pos >= len(data):
                break
            marker = data[pos]
            pos += 1
            if marker == 0xDA or marker == 0xD9:
                break
            if marker == 0xD8 or 0xD0 <= marker <= 0xD7:
                continue
            if pos + 2 > len(data):
                break
            seg_len = struct.unpack(">H", data[pos : pos + 2])[0]
            if seg_len < 2 or pos + seg_len > len(data):
                break
            payload = data[pos + 2 : pos + seg_len]
            if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                return _parse_tiff_exif(payload[6:])
            pos += seg_len
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        pos = 8
        while pos + 12 <= len(data):
            length = struct.unpack(">I", data[pos : pos + 4])[0]
            ctype = data[pos + 4 : pos + 8]
            if pos + 12 + length > len(data):
                break
            if ctype == b"eXIf":
                payload = data[pos + 8 : pos + 8 + length]
                if payload.startswith(b"Exif\x00\x00"):
                    payload = payload[6:]
                return _parse_tiff_exif(payload)
            if ctype == b"IEND":
                break
            pos += 12 + length
    elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        pos = 12
        while pos + 8 <= len(data):
            fourcc = data[pos : pos + 4]
            size = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
            if pos + 8 + size > len(data):
                break
            if fourcc == b"EXIF":
                payload = data[pos + 8 : pos + 8 + size]
                if payload.startswith(b"Exif\x00\x00"):
                    payload = payload[6:]
                return _parse_tiff_exif(payload)
            pos += 8 + size + (size & 1)
    return {"present": False, "tag_count": 0, "fields": {}}


class _DirectionalTransitionTracker:
    """Tracks alternating opposing extrema jumps (>= delta) across video frames."""

    def __init__(self, delta: float):
        self.delta = delta
        self.initialized = False
        self.min_seen = 0.0
        self.max_seen = 0.0
        self.anchor = 0.0
        self.direction = 0
        self.transitions: list[int] = []

    def push(self, frame_index: int, value: float) -> None:
        if not self.initialized:
            self.initialized = True
            self.min_seen = value
            self.max_seen = value
            self.anchor = value
            return
        if self.direction == 0:
            if value - self.min_seen >= self.delta:
                self.transitions.append(frame_index)
                self.direction = 1
                self.anchor = value
            elif self.max_seen - value >= self.delta:
                self.transitions.append(frame_index)
                self.direction = -1
                self.anchor = value
            else:
                self.min_seen = min(self.min_seen, value)
                self.max_seen = max(self.max_seen, value)
        elif self.direction == 1:
            if value > self.anchor:
                self.anchor = value
            elif self.anchor - value >= self.delta:
                self.transitions.append(frame_index)
                self.direction = -1
                self.anchor = value
        else:
            if value < self.anchor:
                self.anchor = value
            elif value - self.anchor >= self.delta:
                self.transitions.append(frame_index)
                self.direction = 1
                self.anchor = value


def _flash_windows_from_transitions(
    frame_indices: list[int],
    frame_count: int,
    duration: float,
    min_hz: float,
) -> tuple[list[dict], float]:
    if frame_count <= 1 or duration <= 0 or not frame_indices:
        return [], 0.0
    dt = duration / frame_count
    times = [min(duration, idx * dt) for idx in frame_indices]
    min_transitions = max(2, int(math.ceil(min_hz * 2.0)))
    max_rate_hz = 0.0
    raw_windows: list[tuple[float, float]] = []

    right = 0
    n = len(times)
    for left in range(n):
        t_start = times[left]
        while right < n and (times[right] - t_start) < 1.0 - 1e-9:
            right += 1
        count_in_1s = right - left
        rate_hz = count_in_1s / 2.0
        if rate_hz > max_rate_hz:
            max_rate_hz = rate_hz
        if count_in_1s >= min_transitions:
            w_end = min(duration, max(times[right - 1], t_start + dt))
            if w_end > t_start:
                raw_windows.append((t_start, w_end))

    if not raw_windows:
        return [], round(max_rate_hz, 4)

    merged: list[dict] = []
    cur_start, cur_end = raw_windows[0]
    for s, e in raw_windows[1:]:
        if s <= cur_end + 0.25:
            cur_end = max(cur_end, e)
        else:
            merged.append(
                {"start_seconds": round(cur_start, 6), "end_seconds": round(cur_end, 6)}
            )
            cur_start, cur_end = s, e
    merged.append(
        {"start_seconds": round(cur_start, 6), "end_seconds": round(cur_end, 6)}
    )
    return merged, round(max_rate_hz, 4)


def _decode_video_with_scan(command: list[str], duration: float, timeout: int = 240) -> dict:
    """Run single-decode FFmpeg streaming 64x36 rgb24 frames while capturing filter logs."""
    frame_bytes = 64 * 36 * 3
    pixel_scale = 64 * 36 * 255.0
    luma_tracker = _DirectionalTransitionTracker(THRESHOLDS["flash_luma_delta"])
    red_tracker = _DirectionalTransitionTracker(THRESHOLDS["flash_red_delta"])

    try:
        proc_cm = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except OSError as exc:
        raise MediaError(
            "media tool unavailable or processing deadline exceeded"
        ) from exc

    with proc_cm as proc:
        stderr_chunks: list[bytes] = []
        stderr_size = 0

        def _drain_stderr():
            nonlocal stderr_size
            assert proc.stderr is not None
            while chunk := proc.stderr.read(65536):
                if stderr_size < 16 * 1024 * 1024:
                    stderr_chunks.append(chunk)
                    stderr_size += len(chunk)

        reader = threading.Thread(target=_drain_stderr, daemon=True)
        reader.start()

        deadline = time.monotonic() + timeout
        carry = bytearray()
        frame_count = 0
        first_frame: bytes | None = None
        last_frame: bytes | None = None

        try:
            assert proc.stdout is not None
            while True:
                if time.monotonic() > deadline:
                    proc.kill()
                    raise MediaError(
                        "media tool unavailable or processing deadline exceeded"
                    )
                chunk = proc.stdout.read(frame_bytes * 64)
                if not chunk:
                    break
                carry.extend(chunk)
                usable = (len(carry) // frame_bytes) * frame_bytes
                if usable == 0:
                    continue
                for offset in range(0, usable, frame_bytes):
                    fb = bytes(carry[offset : offset + frame_bytes])
                    if first_frame is None:
                        first_frame = fb
                    sr = sum(fb[0::3])
                    sg = sum(fb[1::3])
                    sb = sum(fb[2::3])
                    y = (0.2126 * sr + 0.7152 * sg + 0.0722 * sb) / pixel_scale
                    rgb_total = sr + sg + sb
                    red_state = (
                        max(0.0, (sr - sg - sb) / pixel_scale)
                        if rgb_total > 0
                        and (sr / rgb_total) >= THRESHOLDS["flash_red_ratio"]
                        else 0.0
                    )
                    luma_tracker.push(frame_count, y)
                    red_tracker.push(frame_count, red_state)
                    frame_count += 1
                    last_frame = fb
                del carry[:usable]

            remaining_time = max(0.5, deadline - time.monotonic())
            proc.wait(timeout=remaining_time)
            reader.join(timeout=2.0)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            proc.wait()
            reader.join(timeout=2.0)
            raise MediaError(
                "media tool unavailable or processing deadline exceeded"
            ) from exc
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            reader.join(timeout=2.0)

        returncode = proc.returncode

    if returncode:
        raise MediaError("media decode failed")

    luma_spans, luma_hz = _flash_windows_from_transitions(
        luma_tracker.transitions, frame_count, duration, THRESHOLDS["flash_min_hz"]
    )
    red_spans, red_hz = _flash_windows_from_transitions(
        red_tracker.transitions, frame_count, duration, THRESHOLDS["flash_min_hz"]
    )
    all_flash = sorted(luma_spans + red_spans, key=lambda item: item["start_seconds"])
    merged_flash: list[dict] = []
    for span in all_flash:
        if merged_flash and span["start_seconds"] <= merged_flash[-1]["end_seconds"] + 0.25:
            merged_flash[-1]["end_seconds"] = round(
                max(merged_flash[-1]["end_seconds"], span["end_seconds"]), 6
            )
        else:
            merged_flash.append(dict(span))

    return {
        "log": b"".join(stderr_chunks).decode("utf-8", errors="replace"),
        "frame_count": frame_count,
        "first_frame": first_frame,
        "last_frame": last_frame,
        "flash_spans": merged_flash,
        "max_flash_rate_hz": max(luma_hz, red_hz),
    }


def _default_max_duration() -> float:
    raw = os.environ.get("SIGNAL_MAX_DURATION_SECONDS")
    if raw is None or not raw.strip():
        return THRESHOLDS["max_duration_seconds"]
    value = float(raw)
    if not math.isfinite(value) or value <= 0:
        raise MediaError("invalid configured duration ceiling")
    return value


def _parse_duration(metadata: dict, stream: dict | None = None) -> float:
    raw = metadata.get("format", {}).get("duration")
    if raw is None and stream is not None:
        raw = stream.get("duration")
    try:
        duration = float(raw)
    except (ValueError, TypeError) as exc:
        raise MediaError("finite media duration is required") from exc
    if not math.isfinite(duration):
        raise MediaError("finite media duration is required")
    return duration


def analyze(
    path: Path,
    *,
    snapshot_id: str = "local",
    input_sha256: str | None = None,
    expected_sha256: str | None = None,
    expected_size_bytes: int | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
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

    image_magic = _detect_still_image_magic(path)
    metadata = probe(path)
    streams = metadata.get("streams", [])
    fmt_name = metadata.get("format", {}).get("format_name", "")
    fmt_tokens = {tok.strip() for tok in fmt_name.split(",") if tok.strip()}

    video = [
        s
        for s in streams
        if s.get("codec_type") == "video"
        and not s.get("disposition", {}).get("attached_pic")
    ]
    audio = [s for s in streams if s.get("codec_type") == "audio"]

    is_image = image_magic is not None or (
        bool(fmt_tokens & IMAGE_FORMATS)
        and len(video) == 1
        and len(audio) == 0
        and video[0].get("codec_name") in IMAGE_CODECS
    )

    if is_image:
        if len(video) != 1 or len(audio) != 0:
            raise MediaError("still image must contain one image stream and no audio")
        v = video[0]
        if v.get("codec_name") and v.get("codec_name") not in IMAGE_CODECS:
            raise MediaError("unsupported still image codec")
        width = v.get("width", 0)
        height = v.get("height", 0)
        if not 0 < width <= 4096 or not 0 < height <= 4096:
            raise MediaError("image dimensions exceed processing scope")
        _run(
            [
                "ffmpeg",
                "-hide_banner",
                "-nostdin",
                "-v",
                "error",
                "-xerror",
                "-protocol_whitelist",
                "file,pipe",
                "-format_whitelist",
                "image2,jpeg_pipe,png_pipe,webp_pipe",
                "-i",
                str(path),
                "-frames:v",
                "1",
                "-f",
                "null",
                "-",
            ],
            timeout=30,
        )
        modality = "image"
        duration = None
        exif_info = extract_exif(path)
        log = ""
        scan = None
    elif len(video) == 0 and len(audio) == 1:
        if fmt_tokens and not (fmt_tokens & AUDIO_FORMATS):
            raise MediaError("unsupported audio container format")
        modality = "audio"
        duration = _parse_duration(metadata, audio[0])
        min_dur = (
            THRESHOLDS["audio_min_seconds"]
            if min_duration_seconds is None
            else float(min_duration_seconds)
        )
        max_dur = (
            _default_max_duration()
            if max_duration_seconds is None
            else float(max_duration_seconds)
        )
        if not min_dur <= duration <= max_dur + 0.1:
            raise MediaError(
                f"audio duration must be {min_dur:g}–{max_dur:g} seconds"
            )
        decode_cap = str(int(math.ceil(max_dur)) + 2)
        decoded = _run(
            [
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
                FORMAT_WHITELIST,
                "-i",
                str(path),
                "-t",
                decode_cap,
                "-map",
                f"0:{audio[0]['index']}",
                "-af",
                "silencedetect=n=-50dB:d=0.5,volumedetect",
                "-threads",
                "2",
                "-f",
                "null",
                "-",
            ],
            timeout=max(120, int(max_dur * 0.5) + 60),
        )
        log = decoded.stderr.decode("utf-8", errors="replace")
        v = None
        exif_info = None
        scan = None
    elif len(video) == 1 and len(audio) <= 1:
        if fmt_tokens and not (fmt_tokens & VIDEO_FORMATS):
            raise MediaError("unsupported video container format")
        modality = "video"
        v = video[0]
        duration = _parse_duration(metadata)
        min_dur = (
            THRESHOLDS["video_min_seconds"]
            if min_duration_seconds is None
            else float(min_duration_seconds)
        )
        max_dur = (
            _default_max_duration()
            if max_duration_seconds is None
            else float(max_duration_seconds)
        )
        if not min_dur <= duration <= max_dur + 0.1:
            raise MediaError(
                f"media duration must be {min_dur:g}–{max_dur:g} seconds"
            )
        if "duration" in v and abs(float(v["duration"]) - duration) > 0.2:
            raise MediaError("video track does not cover the container timeline")
        if not 0 < v.get("width", 0) <= 4096 or not 0 < v.get("height", 0) <= 4096:
            raise MediaError("video dimensions exceed processing scope")
        decode_cap = str(int(math.ceil(max_dur)) + 2)
        v_idx = v["index"]
        filter_complex = (
            f"[0:{v_idx}]split=2[vt][vf];"
            "[vt]blackdetect=d=0.5:pix_th=0.05:pic_th=0.98,freezedetect=n=-60dB:d=2[vnull];"
            "[vf]scale=64:36:flags=bilinear,format=rgb24[vraw]"
        )
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
            "mov,mp4,m4a,3gp,matroska,webm",
            "-i",
            str(path),
            "-t",
            decode_cap,
            "-filter_threads",
            "1",
            "-filter_complex",
            filter_complex,
            "-map",
            "[vnull]",
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
        command.extend(
            [
                "-threads",
                "2",
                "-f",
                "null",
                "-",
                "-map",
                "[vraw]",
                "-f",
                "rawvideo",
                "pipe:1",
            ]
        )
        scan = _decode_video_with_scan(
            command, duration, timeout=max(120, int(max_dur * 0.5) + 60)
        )
        log = scan["log"]
        exif_info = None
    else:
        raise MediaError(
            "supported inputs are single-stream video (<=1 audio), standalone audio, or still JPEG/PNG/WebP images"
        )

    c2pa_report = inspect_c2pa(path)

    evidence = []
    signals = []
    flags = []

    def measurement(
        signal_id,
        value,
        unit,
        *,
        status="measured",
        method_id=METHOD_BUNDLE,
        limitation=None,
        evidence_ids=None,
    ):
        signals.append(
            {
                "signal_id": signal_id,
                "kind": "measurement",
                "status": status,
                "value": value,
                "unit_or_scale": unit,
                "method_id": method_id,
                "confidence": {
                    "status": "not_applicable",
                    "probability": None,
                    "calibration_id": None,
                },
                "evidence_ids": evidence_ids or [],
                "limitations": [limitation] if limitation else [],
            }
        )

    measurement("media.modality", modality, "modality")

    if modality in ("video", "audio"):
        measurement(
            "media.duration",
            round(duration, 6),
            "seconds",
            limitation="Container duration; endpoint tolerance 0.1 seconds.",
        )
    else:
        measurement(
            "media.duration",
            None,
            "seconds",
            status="not_applicable",
            limitation="Still image has no temporal duration.",
        )

    if modality in ("video", "image"):
        measurement("media.width", v["width"], "pixels")
        measurement("media.height", v["height"], "pixels")
        measurement(
            "media.aspect_ratio",
            round(v["width"] / v["height"], 6),
            "ratio",
        )
    else:
        measurement(
            "media.width",
            None,
            "pixels",
            status="not_applicable",
            limitation="Standalone audio has no video frame dimensions.",
        )
        measurement(
            "media.height",
            None,
            "pixels",
            status="not_applicable",
            limitation="Standalone audio has no video frame dimensions.",
        )
        measurement(
            "media.aspect_ratio",
            None,
            "ratio",
            status="not_applicable",
            limitation="Standalone audio has no video frame dimensions.",
        )

    if modality == "image":
        measurement(
            "media.exif",
            exif_info,
            "exif_summary",
            limitation="Technical TIFF/EXIF header fields only; GPS coordinates are omitted and metadata can be edited.",
        )
        measurement(
            "media.audio_track_count",
            None,
            "tracks",
            status="not_applicable",
            limitation="Still image container has no audio tracks.",
        )
        measurement(
            "accessibility.embedded_caption_track_count",
            None,
            "tracks",
            status="not_applicable",
            limitation="Still image has no timed subtitle tracks.",
        )
    else:
        measurement(
            "media.exif",
            None,
            "exif_summary",
            status="not_applicable",
            limitation="EXIF IFD extraction applies to still images only.",
        )
        measurement("media.audio_track_count", len(audio), "tracks")
        if modality == "video":
            measurement(
                "accessibility.embedded_caption_track_count",
                sum(s.get("codec_type") == "subtitle" for s in streams),
                "tracks",
                limitation=UNSUPPORTED["caption_completeness"],
            )
        else:
            measurement(
                "accessibility.embedded_caption_track_count",
                None,
                "tracks",
                status="not_applicable",
                limitation="Standalone audio has no video subtitle track container requirement.",
            )

    if modality == "video":
        black_spans = intervals(log, "black_start", "black_end", duration)
        for signal_id, start, end, flag_code in [
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
        ]:
            spans = (
                black_spans
                if signal_id == "technical.black_segments"
                else intervals(log, start, end, duration)
            )
            ids = []
            for span in spans:
                evidence_id = f"e{len(evidence) + 1}"
                ids.append(evidence_id)
                evidence.append(
                    {
                        "id": evidence_id,
                        "media_sha256": digest,
                        "modality": "video",
                        **span,
                    }
                )
                explained_by_black = signal_id == "technical.static_segments" and any(
                    max(
                        0,
                        min(span["end_seconds"], black["end_seconds"])
                        - max(span["start_seconds"], black["start_seconds"]),
                    )
                    / (span["end_seconds"] - span["start_seconds"])
                    >= THRESHOLDS["static_flag_black_overlap_ratio"]
                    for black in black_spans
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

        flash_ids = []
        for span in scan["flash_spans"]:
            evidence_id = f"e{len(evidence) + 1}"
            flash_ids.append(evidence_id)
            evidence.append(
                {
                    "id": evidence_id,
                    "media_sha256": digest,
                    "modality": "video",
                    **span,
                }
            )
            flags.append(
                {
                    "code": "photosensitive_flash_observed",
                    "signal_id": "accessibility.flash_segments",
                    "evidence_ids": [evidence_id],
                    "review_state": "unreviewed",
                    "automatic_action": "none",
                    "interpretation": "Sustained >= 4 Hz luminance or saturated-red transitions observed; clinical photosensitivity compliance requires specialist review.",
                }
            )
        measurement(
            "accessibility.flash_segments",
            len(scan["flash_spans"]),
            "segments",
            evidence_ids=flash_ids,
            limitation="64x36 frame-mean luminance (>=10% jump) and saturated-red (>=20% jump) screening at >=4 Hz; localized sub-frame spatial patterns are approximated.",
        )
        measurement(
            "accessibility.max_flash_rate_hz",
            scan["max_flash_rate_hz"],
            "Hz",
            evidence_ids=flash_ids,
            limitation="Peak opposing-transition flash rate over 1-second sliding windows.",
        )
    else:
        non_video_reason = (
            "Standalone audio has no video frames."
            if modality == "audio"
            else "Still image has no temporal frame sequence."
        )
        for signal_id, unit in (
            ("technical.black_segments", "segments"),
            ("technical.static_segments", "segments"),
            ("accessibility.flash_segments", "segments"),
            ("accessibility.max_flash_rate_hz", "Hz"),
        ):
            measurement(
                signal_id,
                None,
                unit,
                status="not_applicable",
                limitation=non_video_reason,
            )

    if audio and modality in ("video", "audio"):
        silent_spans = intervals(log, "silence_start", "silence_end", duration)
        silent_ids = []
        for span in silent_spans:
            evidence_id = f"e{len(evidence) + 1}"
            silent_ids.append(evidence_id)
            evidence.append(
                {
                    "id": evidence_id,
                    "media_sha256": digest,
                    "modality": "audio",
                    **span,
                }
            )
            flags.append(
                {
                    "code": "silence_observed",
                    "signal_id": "technical.silent_segments",
                    "evidence_ids": [evidence_id],
                    "review_state": "unreviewed",
                    "automatic_action": "none",
                    "interpretation": "Observable pattern; intent, harm and editorial appropriateness are not inferred.",
                }
            )
        measurement(
            "technical.silent_segments",
            len(silent_spans),
            "segments",
            evidence_ids=silent_ids,
            limitation="Thresholded full-decode observation; deliberate black screens, still images and silence may be appropriate.",
        )
        for name in ("mean_volume", "max_volume"):
            measurement(
                f"technical.{name}",
                _volume(log, name),
                "dBFS",
                status="measured",
                limitation="First audio track; null denotes no audio or a non-finite value for digital silence. Not a speech intelligibility measure.",
            )
    else:
        no_audio_reason = (
            "Still image has no audio stream."
            if modality == "image"
            else "No audio stream."
        )
        measurement(
            "technical.silent_segments",
            None,
            "segments",
            status="not_applicable",
            limitation=no_audio_reason,
        )
        for name in ("mean_volume", "max_volume"):
            measurement(
                f"technical.{name}",
                None,
                "dBFS",
                status="not_applicable",
                limitation="First audio track; null denotes no audio or a non-finite value for digital silence. Not a speech intelligibility measure.",
            )

    c2pa_evidence_ids = []
    if c2pa_report["status"] == "tampered_payload":
        evidence_id = f"e{len(evidence) + 1}"
        c2pa_evidence_ids.append(evidence_id)
        evidence.append(
            {
                "id": evidence_id,
                "media_sha256": digest,
                "modality": modality,
                "start_seconds": 0.0,
                "end_seconds": round(duration, 6) if duration is not None else 0.0,
            }
        )
        flags.append(
            {
                "code": "c2pa_tampered_payload",
                "signal_id": "provenance.c2pa",
                "evidence_ids": [evidence_id],
                "review_state": "unreviewed",
                "automatic_action": "none",
                "interpretation": "Embedded C2PA Content Credentials failed offline digest or signature integrity verification.",
            }
        )
    measurement(
        "provenance.c2pa",
        c2pa_report,
        "c2pa_inspection",
        method_id=C2PA_METHOD_ID,
        evidence_ids=c2pa_evidence_ids,
        limitation=c2pa_report["reason"],
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
            "modality": modality,
            "technical_decode": "full",
            "c2pa_inspection": "offline_jumbf",
            "flash_screening": "screened" if modality == "video" else "not_applicable",
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
