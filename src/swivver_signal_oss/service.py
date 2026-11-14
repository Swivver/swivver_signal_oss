"""Standalone media application; Core is an optional HTTP client, never a dependency."""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path

from .jobs import Store
from .media import METHOD_BUNDLE, MediaError, analyze

DIGEST = re.compile(r"^[a-f0-9]{64}$")
MAX_BYTES = 512 * 1024 * 1024


class Application:
    api_version = "1.0.0"

    def __init__(
        self,
        root: Path,
        *,
        workers=2,
        allowed_hosts=(),
        max_pending=1000,
        evaluator=None,
        retention_hours: float | None = None,
        reaper_interval_seconds: float = 60.0,
    ):
        if (
            not isinstance(workers, int)
            or isinstance(workers, bool)
            or not 1 <= workers <= 16
            or not isinstance(max_pending, int)
            or isinstance(max_pending, bool)
            or not 1 <= max_pending <= 10000
        ):
            raise ValueError("invalid worker or queue limit")
        if retention_hours is None:
            env_ret = os.environ.get("SIGNAL_RETENTION_HOURS", "").strip()
            if env_ret:
                retention_hours = float(env_ret)
        if retention_hours is not None:
            if (
                isinstance(retention_hours, bool)
                or not isinstance(retention_hours, (int, float))
                or not math.isfinite(retention_hours)
                or retention_hours < 0
            ):
                raise ValueError("invalid retention_hours")
        if (
            isinstance(reaper_interval_seconds, bool)
            or not isinstance(reaper_interval_seconds, (int, float))
            or not math.isfinite(reaper_interval_seconds)
            or reaper_interval_seconds <= 0
        ):
            raise ValueError("invalid reaper_interval_seconds")
        self.store = Store(root)
        self.workers = workers
        self.allowed_hosts = set(allowed_hosts)
        self.max_pending = max_pending
        self.evaluator = evaluator or analyze
        self.retention_hours = (
            float(retention_hours)
            if retention_hours is not None and retention_hours > 0
            else None
        )
        self.reaper_interval_seconds = float(reaper_interval_seconds)
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.threads = []
        self.reaper_thread: threading.Thread | None = None
        self.failures = 0
        self.failure_lock = threading.Lock()
        self.evidence_engine = None
        self.engines = {}

    def register_engine(self, name, engine):
        if self.threads or name in self.capabilities():
            raise ValueError("engines must be uniquely registered before starting")
        self.engines[name] = engine

    def openapi(self):
        from .api import openapi

        return openapi()

    def install_evidence_engine(self, engine, *, multilingual_engine=None):
        if multilingual_engine is not None:
            engine.multilingual_engine = multilingual_engine
        self.evidence_engine = engine

    def start(self):
        if self.threads:
            return
        if self.retention_hours is not None:
            self.store.reap(self.retention_hours * 3600.0)
            self.reaper_thread = threading.Thread(
                target=self._reap_loop, name="signal-reaper", daemon=True
            )
            self.reaper_thread.start()
        for index in range(self.workers):
            thread = threading.Thread(
                target=self.work, name=f"signal-worker-{index}", daemon=True
            )
            thread.start()
            self.threads.append(thread)

    def _reap_loop(self):
        while not self.stop_event.wait(self.reaper_interval_seconds):
            try:
                if self.retention_hours is not None:
                    self.store.reap(self.retention_hours * 3600.0)
            except Exception:
                with self.failure_lock:
                    self.failures += 1

    def close(self):
        self.stop_event.set()
        self.wake.set()
        deadline = time.monotonic() + 240
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if self.reaper_thread is not None:
            self.reaper_thread.join(timeout=max(0, deadline - time.monotonic()))

    def ingest(self, owner, stream, size, expected=None):
        if not 0 < size <= MAX_BYTES:
            raise MediaError("invalid media size")
        if expected is not None and not DIGEST.fullmatch(expected):
            raise MediaError("invalid checksum")
        directory = (
            self.store.root / "assets" / hashlib.sha256(owner.encode()).hexdigest()
        )
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = None
        try:
            with tempfile.NamedTemporaryFile(dir=directory, delete=False) as temporary:
                path = Path(temporary.name)
                digest = hashlib.sha256()
                remaining = size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise MediaError("incomplete upload")
                    digest.update(chunk)
                    temporary.write(chunk)
                    remaining -= len(chunk)
                temporary.flush()
                os.fsync(temporary.fileno())
            actual = digest.hexdigest()
            if expected is not None and expected != actual:
                raise MediaError("media checksum mismatch")
            target = directory / (actual + ".media")
            path.replace(target)
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            path = None
            return self.store.add_asset(owner, actual, size, target)
        finally:
            if path is not None:
                path.unlink(missing_ok=True)

    def normalize(self, owner, request):
        if not isinstance(request, dict):
            raise MediaError("request must be an object")
        if request.get("method_bundle") in self.engines:
            return self.engines[request["method_bundle"]].normalize(
                owner, request, self
            )
        if set(request) - {
            "asset_id",
            "media",
            "method_bundle",
            "binding",
            "claims",
            "sources",
            "language",
        }:
            raise MediaError("unknown request field")
        bundle = request.get("method_bundle", METHOD_BUNDLE)
        if bundle not in self.capabilities():
            raise MediaError("unsupported method bundle")
        result = {"method_bundle": bundle}
        binding = request.get("binding", {})
        if not isinstance(binding, dict) or set(binding) - {
            "snapshot_id",
            "input_sha256",
        }:
            raise MediaError("invalid binding")
        if binding:
            if (
                not isinstance(binding.get("snapshot_id"), str)
                or not 0 < len(binding["snapshot_id"]) <= 100
            ):
                raise MediaError("invalid reference")
            if not isinstance(binding.get("input_sha256"), str) or not DIGEST.fullmatch(
                binding["input_sha256"]
            ):
                raise MediaError("invalid input digest")
            result["binding"] = binding
        if bundle == "source-evidence-nli-v1":
            language = request.get("language")
            if language not in ("en", "pt", "es"):
                raise MediaError(
                    "this evidence bundle requires an explicit language declaration (en, pt, or es)"
                )
            result["language"] = language
            if "asset_id" in request or "media" in request:
                raise MediaError("evidence bundle takes explicit text sources")
            result.update(
                self.evidence_engine.validate(
                    request.get("claims"),
                    request.get("sources"),
                    language=language,
                )
            )
            return result
        if ("asset_id" in request) == ("media" in request):
            raise MediaError("provide one asset or media URL")
        if "asset_id" in request:
            if not isinstance(request["asset_id"], str) or not re.fullmatch(
                "[a-f0-9]{32}", request["asset_id"]
            ):
                raise MediaError("invalid asset identity")
            asset = self.store.asset(owner, request["asset_id"])
            result.update(
                asset_id=asset["id"],
                sha256=asset["sha256"],
                size_bytes=asset["size_bytes"],
            )
        else:
            media = request["media"]
            if not isinstance(media, dict) or set(media) != {
                "url",
                "sha256",
                "size_bytes",
            }:
                raise MediaError("invalid media reference")
            if not isinstance(media["url"], str) or len(media["url"]) > 4096:
                raise MediaError("invalid media URL")
            if not isinstance(media["sha256"], str) or not DIGEST.fullmatch(
                media["sha256"]
            ):
                raise MediaError("invalid checksum")
            if (
                not isinstance(media["size_bytes"], int)
                or isinstance(media["size_bytes"], bool)
                or not 0 < media["size_bytes"] <= MAX_BYTES
            ):
                raise MediaError("invalid media size")
            from .server import allowed_url

            allowed_url(media["url"], self.allowed_hosts)
            result["media"] = media
        if "claims" in request or "sources" in request:
            raise MediaError("technical bundle does not evaluate claims")
        return result

    def submit(self, owner, key, request):
        if not isinstance(key, str) or not 0 < len(key.strip()) <= 200:
            raise MediaError("Idempotency-Key is required")
        job = self.store.submit(
            owner, key, self.normalize(owner, request), max_pending=self.max_pending
        )
        self.wake.set()
        return job

    def capabilities(self):
        return (
            [METHOD_BUNDLE]
            + (["source-evidence-nli-v1"] if self.evidence_engine is not None else [])
            + list(self.engines)
        )

    def evaluate(self, job):
        request = job["request"]
        if request["method_bundle"] in self.engines:
            return self.engines[request["method_bundle"]].evaluate(job, self)
        binding = request.get("binding", {})
        reference = binding.get("snapshot_id", job["id"])
        input_hash = binding.get("input_sha256", job["request_hash"])
        if request["method_bundle"] == "source-evidence-nli-v1":
            return self.evidence_engine.evaluate(request, reference, input_hash)
        if "asset_id" in request:
            asset = self.store.asset(job["owner"], request["asset_id"])
        else:
            from .server import download

            with tempfile.TemporaryDirectory(dir=self.store.root) as directory:
                path = Path(directory) / "input.media"
                media = request["media"]
                download(media["url"], path, self.allowed_hosts, media["size_bytes"])
                with path.open("rb") as stream:
                    asset = self.ingest(
                        job["owner"], stream, media["size_bytes"], media["sha256"]
                    )
        return self.evaluator(
            Path(asset["path"]),
            snapshot_id=reference,
            input_sha256=input_hash,
            expected_sha256=asset["sha256"],
            expected_size_bytes=asset["size_bytes"],
        )

    def work(self):
        while not self.stop_event.is_set():
            try:
                job = self.store.claim()
                if job is None:
                    self.wake.wait(0.1)
                    self.wake.clear()
                    continue
                try:
                    profile = self.evaluate(job)
                    self.store.finish(job, profile=profile)
                except MediaError:
                    self.store.finish(job, error_code="invalid_media_or_scope")
                except (OSError, TimeoutError):
                    self.store.finish(job, error_code="media_unavailable", retry=True)
                except Exception:
                    self.store.finish(job, error_code="evaluation_failed", retry=True)
            except Exception:
                with self.failure_lock:
                    self.failures += 1
                self.stop_event.wait(0.1)

    def public_job(self, job):
        return {
            k: job[k]
            for k in (
                "id",
                "state",
                "attempts",
                "created_at",
                "started_at",
                "finished_at",
                "error_code",
                "profile",
            )
        }

    def ready(self):
        self.store.statistics()
        return (
            bool(shutil.which("ffmpeg") and shutil.which("ffprobe"))
            and len(self.threads) == self.workers
            and all(t.is_alive() for t in self.threads)
            and (self.reaper_thread is None or self.reaper_thread.is_alive())
            and not self.stop_event.is_set()
        )
