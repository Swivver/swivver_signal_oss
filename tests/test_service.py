import hashlib
import http.client
import json
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from swivver_signal_oss.jobs import Capacity, Conflict, LeaseLost, NotFound, Store
from swivver_signal_oss.server import make_server
from swivver_signal_oss.service import Application


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1000.0
        self.store = Store(Path(self.temp.name), clock=lambda: self.now)

    def test_concurrent_idempotency_and_tenant_isolation(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            jobs = list(
                pool.map(
                    lambda _: self.store.submit("one", "stable", {"asset": "hash"}),
                    range(16),
                )
            )
        self.assertEqual(len({j["id"] for j in jobs}), 1)
        with self.assertRaises(Conflict):
            self.store.submit("one", "stable", {"asset": "changed"})
        with self.assertRaises(NotFound):
            self.store.get("two", jobs[0]["id"])
        other = self.store.submit("two", "stable", {"asset": "hash"})
        self.assertNotEqual(other["id"], jobs[0]["id"])
        with self.assertRaises(Capacity):
            self.store.submit("one", "next", {}, max_pending=2)
        self.assertEqual(self.store.statistics()["states"]["queued"], 2)

    def test_lease_fence_restart_and_immutable_results(self):
        job = self.store.submit("one", "stable", {"asset": "hash"})
        first = self.store.claim(lease_seconds=10)
        self.assertEqual(first["id"], job["id"])
        self.now += 11
        restarted = Store(Path(self.temp.name), clock=lambda: self.now)
        second = restarted.claim(lease_seconds=10)
        with self.assertRaises(LeaseLost):
            self.store.finish(first, profile={"wrong": "old worker"})
        restarted.finish(second, profile={"correct": "new worker"})
        self.assertEqual(
            self.store.get("one", job["id"])["profile"], {"correct": "new worker"}
        )
        with self.store.connection(write=True) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(
                    "UPDATE assessments SET result_json='{}' WHERE id=?", (job["id"],)
                )

    def test_retry_and_crash_exhaustion(self):
        job = self.store.submit("one", "retry", {})
        for n in range(3):
            attempt = self.store.claim()
            self.assertEqual(attempt["attempts"], n + 1)
            self.store.finish(attempt, error_code="transient", retry=True)
            self.now += 31
        self.assertEqual(self.store.get("one", job["id"])["state"], "failed")
        job = self.store.submit("one", "crashes", {})
        for _ in range(3):
            self.assertIsNotNone(self.store.claim(lease_seconds=1))
            self.now += 2
        self.assertIsNone(self.store.claim())
        self.assertEqual(
            self.store.get("one", job["id"])["error_code"], "lease_exhausted"
        )

    def test_signed_url_rotation_preserves_command_identity(self):
        body = {
            "media": {
                "url": "https://media.example/a?signature=first",
                "sha256": "a" * 64,
                "size_bytes": 100,
            }
        }
        first = self.store.submit("one", "key", body)
        body["media"]["url"] = "https://media.example/a?signature=refreshed"
        self.assertEqual(self.store.submit("one", "key", body)["id"], first["id"])


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.video = Path(cls.fixture.name) / "media.mp4"
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
                "-t",
                "10",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(cls.video),
            ],
            check=True,
            capture_output=True,
        )
        cls.media = cls.video.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = Application(Path(self.temp.name), workers=2)
        self.server = make_server(
            "127.0.0.1",
            0,
            self.app,
            {"partner": "partner-token", "other": "other-token"},
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.app.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.server.shutdown()
        self.server.server_close()
        self.app.close()
        self.thread.join()
        self.temp.cleanup()

    def request(
        self, method, path, body=None, token="partner-token", key=None, extra=None
    ):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=20)
        headers = {"Authorization": "Bearer " + token}
        if key is not None:
            headers["Idempotency-Key"] = key
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        headers.update(extra or {})
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        status = r.status
        c.close()
        return status, json.loads(data) if data.startswith((b"{", b"[")) else data

    def wait(self, identity):
        for _ in range(200):
            status, job = self.request("GET", "/v1/assessments/" + identity)
            if job["state"] in ("completed", "failed"):
                return job
            time.sleep(0.02)
        self.fail("job did not finish")

    def test_actual_upload_assessment_receipt_and_result(self):
        checksum = hashlib.sha256(self.media).hexdigest()
        status, asset = self.request(
            "POST", "/v1/assets", self.media, extra={"X-Content-SHA256": checksum}
        )
        self.assertEqual(status, 201)
        self.assertEqual(asset["sha256"], checksum)
        status, again = self.request("POST", "/v1/assets", self.media)
        self.assertEqual(again["id"], asset["id"])
        body = {"asset_id": asset["id"]}
        status, receipt = self.request(
            "POST", "/v1/assessments", body, key="generic-media"
        )
        self.assertEqual(status, 202)
        self.assertEqual(
            self.request("POST", "/v1/assessments", body, key="generic-media")[1],
            receipt,
        )
        job = self.wait(receipt["id"])
        self.assertEqual(job["state"], "completed")
        self.assertEqual(job["profile"]["subject"]["media_sha256"], checksum)
        self.assertEqual(job["profile"]["subject"]["snapshot_id"], receipt["id"])
        self.assertEqual(
            self.request(
                "GET", "/v1/assessments/" + receipt["id"], token="other-token"
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/assessments", body, key="foreign", token="other-token"
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/assessments",
                dict(
                    body, binding={"snapshot_id": "changed", "input_sha256": "a" * 64}
                ),
                key="generic-media",
            )[0],
            409,
        )
        self.assertNotIn("path", asset)
        self.assertNotIn("request", job)
        self.assertIn(
            b'signal_jobs{state="completed"} 1', self.request("GET", "/metrics")[1]
        )
        self.assertEqual(self.request("GET", "/ready")[0], 200)
        self.assertEqual(
            self.request("GET", "/v1/capabilities")[1]["method_bundles"],
            ["ffmpeg-technical-v1"],
        )
        self.assertEqual(self.request("GET", "/openapi.json")[0], 200)

    def test_queue_backpressure_preserves_replay_and_recovers(self):
        self.app.max_pending = 1
        entered = threading.Event()
        release = threading.Event()
        evaluate = self.app.evaluator

        def blocked(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test worker was not released")
            return evaluate(*args, **kwargs)

        self.app.evaluator = blocked
        self.addCleanup(release.set)
        _, asset = self.request("POST", "/v1/assets", self.media)
        body = {"asset_id": asset["id"]}
        status, receipt = self.request(
            "POST", "/v1/assessments", body, key="busy-first"
        )
        self.assertEqual(status, 202)
        self.assertTrue(entered.wait(2))
        self.assertEqual(
            self.request("POST", "/v1/assessments", body, key="busy-first")[1], receipt
        )
        self.assertEqual(
            self.request("POST", "/v1/assessments", body, key="busy-second")[0], 429
        )
        release.set()
        self.assertEqual(self.wait(receipt["id"])["state"], "completed")
        status, second = self.request(
            "POST", "/v1/assessments", body, key="busy-second"
        )
        self.assertEqual(status, 202)
        self.assertEqual(self.wait(second["id"])["state"], "completed")

    def test_invalid_inputs_auth_and_failed_jobs_are_not_clean(self):
        self.assertEqual(
            self.request("POST", "/v1/assets", self.media, token="wrong")[0], 401
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/assets", self.media, extra={"X-Content-SHA256": "0" * 64}
            )[0],
            422,
        )
        self.assertEqual(self.request("POST", "/v1/assessments", {})[0], 422)
        self.assertEqual(
            self.request(
                "POST",
                "/v1/assessments",
                {
                    "media": {
                        "url": "file:///private",
                        "sha256": "a" * 64,
                        "size_bytes": 1,
                    }
                },
                key="bad",
            )[0],
            422,
        )
        status, asset = self.request("POST", "/v1/assets", b"not a video")
        self.assertEqual(status, 201)
        status, receipt = self.request(
            "POST", "/v1/assessments", {"asset_id": asset["id"]}, key="corrupt"
        )
        self.assertEqual(status, 202)
        job = self.wait(receipt["id"])
        self.assertEqual(job["state"], "failed")
        self.assertIsNone(job["profile"])
        self.assertEqual(self.request("GET", "/v1/assessments/missing")[0], 404)
        self.assertEqual(self.request("GET", "/unknown")[0], 404)
        self.assertEqual(self.request("POST", "/unknown", {})[0], 404)

    def test_pending_job_survives_application_restart(self):
        self.app.close()
        _, asset = self.request("POST", "/v1/assets", self.media)
        _, receipt = self.request(
            "POST", "/v1/assessments", {"asset_id": asset["id"]}, key="restart"
        )
        self.assertEqual(
            self.app.store.get("partner", receipt["id"])["state"], "queued"
        )
        replacement = Application(Path(self.temp.name), workers=1)
        replacement.start()
        try:
            job = self.wait(receipt["id"])
            self.assertEqual(job["state"], "completed")
        finally:
            replacement.close()


if __name__ == "__main__":
    unittest.main()
