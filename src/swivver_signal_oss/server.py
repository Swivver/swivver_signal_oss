"""Standalone HTTP API with durable jobs; synchronous v0.1 remains compatible."""

from __future__ import annotations

import hmac
import json
import os
import shutil
import signal
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .jobs import Capacity, Conflict, NotFound
from .media import MediaError
from .service import Application


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def allowed_url(url, allowed_hosts):
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme not in ("http", "https")
        or parts.netloc.lower() not in allowed_hosts
        or parts.username
        or parts.password
        or parts.fragment
    ):
        raise MediaError("media origin is not allowed")


def download(
    url: str, destination: Path, allowed_hosts: set[str], expected_size: int
) -> None:
    allowed_url(url, allowed_hosts)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "Swivver-Signal/0.2"})
    total = 0
    deadline = time.monotonic() + 60
    with opener.open(request, timeout=10) as response, destination.open("wb") as target:
        if response.status != 200:
            raise MediaError("media unavailable")
        while chunk := response.read(1024 * 1024):
            if time.monotonic() > deadline:
                raise MediaError("media download deadline exceeded")
            total += len(chunk)
            if total > expected_size:
                raise MediaError("media exceeds declared size")
            target.write(chunk)
    if total != expected_size:
        raise MediaError("media size mismatch")


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, handler, max_connections=64):
        self.connections = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, address):
        if not self.connections.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\n\r\n"
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.connections.release()


def make_server(
    host, port, app: Application, keys: dict[str, str], *, max_connections=64
):
    if (
        not keys
        or any(
            not isinstance(owner, str)
            or not isinstance(token, str)
            or not owner
            or not token
            for owner, token in keys.items()
        )
        or len(set(keys.values())) != len(keys)
    ):
        raise ValueError("unique nonempty service credentials are required")
    ingress = threading.BoundedSemaphore(8)

    class Handler(BaseHTTPRequestHandler):
        timeout = 30

        def log_message(self, *args):
            pass

        def reply(self, status, body, headers=None):
            data = json.dumps(body, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def principal(self):
            provided = self.headers.get("Authorization", "").encode()
            matched = None
            for owner, token in keys.items():
                if hmac.compare_digest(provided, ("Bearer " + token).encode()):
                    matched = owner
            if matched is None:
                self.reply(401, {"error": "unauthorized"})
            return matched

        def body(self, limit=2 * 1024 * 1024):
            if self.headers.get("Transfer-Encoding"):
                raise MediaError("Content-Length is required")
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= limit:
                raise MediaError("invalid request size")
            data = self.rfile.read(size)
            if len(data) != size:
                raise MediaError("incomplete request")

            def invalid_constant(_):
                raise MediaError("nonfinite JSON value")

            return json.loads(data, parse_constant=invalid_constant)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == "/health":
                self.reply(
                    200, {"service": "swivver-signal", "version": app.api_version}
                )
                return
            if path == "/ready":
                try:
                    ready = app.ready()
                except Exception:
                    ready = False
                self.reply(
                    200 if ready else 503,
                    {
                        "ready": ready,
                        "method_bundles": app.capabilities(),
                        "workers": app.workers,
                    },
                )
                return
            if path == "/openapi.json":
                self.reply(200, app.openapi())
                return
            owner = self.principal()
            if owner is None:
                return
            try:
                if path == "/v1/capabilities":
                    self.reply(
                        200,
                        {
                            "method_bundles": app.capabilities(),
                            "max_bytes": 512 * 1024 * 1024,
                            "max_pending": app.max_pending,
                            "mode": "shadow",
                        },
                    )
                    return
                if path.startswith("/v1/assessments/"):
                    job = app.store.get(owner, path.rsplit("/", 1)[1])
                    self.reply(200, app.public_job(job))
                    return
                if path.startswith("/v1/assets/"):
                    asset = app.store.asset(owner, path.rsplit("/", 1)[1])
                    self.reply(
                        200,
                        {
                            k: asset[k]
                            for k in ("id", "sha256", "size_bytes", "created_at")
                        },
                    )
                    return
                if path == "/metrics":
                    stats = app.store.statistics()
                    lines = ["# TYPE signal_jobs gauge"] + [
                        f'signal_jobs{{state="{state}"}} {stats["states"].get(state,0)}'
                        for state in ("queued", "running", "completed", "failed")
                    ]
                    lines += [
                        f"signal_workers {app.workers}",
                        f"signal_worker_loop_errors_total {app.failures}",
                        f'signal_job_elapsed_seconds_sum {stats["processing_seconds_sum"]}',
                    ]
                    data = ("\n".join(lines) + "\n").encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.reply(404, {"error": "not_found"})
            except NotFound:
                self.reply(404, {"error": "not_found"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            owner = self.principal()
            if owner is None:
                return
            if path not in ("/v1/assets", "/v1/assessments", "/v1/analyze"):
                self.reply(404, {"error": "not_found"})
                return
            if not ingress.acquire(blocking=False):
                self.reply(503, {"error": "ingress_capacity"}, {"Retry-After": "1"})
                return
            try:
                if path == "/v1/assets":
                    size = int(self.headers.get("Content-Length", "0"))
                    if (
                        self.headers.get("Transfer-Encoding")
                        or not 0 < size <= 512 * 1024 * 1024
                    ):
                        self.reply(413, {"error": "invalid_media_size"})
                        return
                    if shutil.disk_usage(app.store.root).free < size + 64 * 1024 * 1024:
                        self.reply(507, {"error": "storage_capacity"})
                        return
                    asset = app.ingest(
                        owner, self.rfile, size, self.headers.get("X-Content-SHA256")
                    )
                    self.reply(
                        201,
                        {
                            k: asset[k]
                            for k in ("id", "sha256", "size_bytes", "created_at")
                        },
                    )
                    return
                request = self.body(8192 if path == "/v1/analyze" else 2 * 1024 * 1024)
                if path == "/v1/analyze":
                    if not isinstance(request, dict):
                        raise MediaError("invalid request")
                    request = {
                        "method_bundle": request.get("method_bundle"),
                        "binding": {
                            "snapshot_id": request.get("snapshot_id"),
                            "input_sha256": request.get("input_sha256"),
                        },
                        "media": {
                            "url": request.get("media_url"),
                            "sha256": request.get("expected_sha256"),
                            "size_bytes": request.get("expected_size_bytes"),
                        },
                    }
                    key = self.headers.get("Idempotency-Key") or hashlib_key(request)
                else:
                    key = self.headers.get("Idempotency-Key", "")
                job = app.submit(owner, key, request)
                if path == "/v1/analyze":
                    deadline = time.monotonic() + 210
                    while (
                        job["state"] not in ("completed", "failed")
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.05)
                        job = app.store.get(owner, job["id"])
                    if job["state"] == "completed":
                        self.reply(200, job["profile"])
                    elif job["state"] == "failed":
                        self.reply(422, {"error": job["error_code"]})
                    else:
                        self.reply(
                            504, {"error": "deadline", "assessment_id": job["id"]}
                        )
                    return
                self.reply(
                    202,
                    {
                        "id": job["id"],
                        "created_at": job["created_at"],
                        "method_bundle": job["request"]["method_bundle"],
                        "mode": "shadow",
                    },
                    {"Location": "/v1/assessments/" + job["id"]},
                )
            except Conflict:
                self.reply(409, {"error": "idempotency_conflict"})
            except Capacity:
                self.reply(429, {"error": "queue_capacity"}, {"Retry-After": "2"})
            except NotFound:
                self.reply(404, {"error": "not_found"})
            except (MediaError, ValueError, KeyError, TypeError):
                self.reply(422, {"error": "invalid_request"})
            except (OSError, TimeoutError):
                self.reply(503, {"error": "io_unavailable"})
            finally:
                ingress.release()

    return BoundedServer((host, port), Handler, max_connections=max_connections)


def hashlib_key(request):
    import hashlib
    from .jobs import canonical

    return hashlib.sha256(canonical(request).encode()).hexdigest()


def serve(
    host,
    port,
    *,
    root=None,
    workers=None,
    evidence_model=None,
    application_factory=None,
):
    token = os.environ.get("SIGNAL_API_TOKEN", "")
    raw_keys = os.environ.get("SIGNAL_API_KEYS_JSON", "")
    keys = json.loads(raw_keys) if raw_keys else {"default": token}
    if not isinstance(keys, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in keys.items()
    ):
        raise ValueError("invalid service credentials")
    allowed = {
        x.strip().lower()
        for x in os.environ.get("SIGNAL_MEDIA_HOSTS", "").split(",")
        if x.strip()
    }
    app = (application_factory or Application)(
        Path(root or os.environ.get("SIGNAL_DATA_DIR", ".signal")),
        workers=workers
        if workers is not None
        else int(os.environ.get("SIGNAL_WORKERS", "2")),
        allowed_hosts=allowed,
        max_pending=int(os.environ.get("SIGNAL_MAX_PENDING", "1000")),
    )
    model = evidence_model or os.environ.get("SIGNAL_EVIDENCE_MODEL")
    if model:
        from .evidence import EvidenceEngine

        app.install_evidence_engine(EvidenceEngine(Path(model)))
    server = make_server(host, port, app, keys)
    app.start()
    previous = {}
    if threading.current_thread() is threading.main_thread():

        def stop(_signum, _frame):
            threading.Thread(target=server.shutdown, daemon=True).start()

        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, stop)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        app.close()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
