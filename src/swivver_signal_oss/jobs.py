"""Independent SQLite job store: WAL durability, tenant guards, quotas, and TTL reaping."""

from __future__ import annotations

import collections
import hashlib
import json
import math
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class Conflict(ValueError):
    pass


class NotFound(ValueError):
    pass


class Capacity(ValueError):
    pass


class RateLimitExceeded(ValueError):
    def __init__(self, message: str = "rate limit exceeded", *, retry_after: int = 1):
        super().__init__(message)
        self.retry_after = max(1, int(retry_after))


class LeaseLost(RuntimeError):
    pass


class SlidingWindowRateLimiter:
    """Thread-safe per-principal sliding-window request rate limiter."""

    def __init__(self, rpm: int, *, window_seconds: float = 60.0, clock=time.monotonic):
        if isinstance(rpm, bool) or not isinstance(rpm, int) or rpm < 1:
            raise ValueError("rate limit rpm must be a positive integer")
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.rpm = rpm
        self.window_seconds = float(window_seconds)
        self.clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, collections.deque[float]] = {}
        self.rejected_total = 0

    def allow(self, principal: str) -> tuple[bool, int]:
        now = float(self.clock())
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._buckets.get(principal)
            if bucket is None:
                bucket = collections.deque()
                self._buckets[principal] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.rpm:
                self.rejected_total += 1
                wait = max(1, int(math.ceil((bucket[0] + self.window_seconds) - now)))
                return False, wait
            bucket.append(now)
            return True, 0


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Store:
    def __init__(self, root: Path, *, clock=time.time):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = self.root / "signal.sqlite3"
        self.clock = clock
        self._reap_lock = threading.Lock()
        self.reaped_assessments = 0
        self.reaped_assets = 0
        with self.connection() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS retention_state (
              id INTEGER PRIMARY KEY CHECK(id=1),
              reap_cutoff REAL
            );
            INSERT OR IGNORE INTO retention_state(id, reap_cutoff) VALUES (1, NULL);
            CREATE TABLE IF NOT EXISTS assets (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, sha256 TEXT NOT NULL,
              size_bytes INTEGER NOT NULL, path TEXT NOT NULL, created_at REAL NOT NULL,
              UNIQUE(owner,sha256));
            CREATE TRIGGER IF NOT EXISTS immutable_asset_update BEFORE UPDATE ON assets
            BEGIN SELECT RAISE(ABORT,'immutable asset'); END;
            DROP TRIGGER IF EXISTS immutable_asset_delete;
            CREATE TRIGGER IF NOT EXISTS immutable_asset_delete BEFORE DELETE ON assets
            WHEN (SELECT reap_cutoff FROM retention_state WHERE id=1) IS NULL
              OR OLD.created_at > (SELECT reap_cutoff FROM retention_state WHERE id=1)
            BEGIN SELECT RAISE(ABORT,'immutable asset'); END;
            CREATE TABLE IF NOT EXISTS assessments (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, idempotency_key TEXT NOT NULL,
              request_hash TEXT NOT NULL, request_json TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('queued','running','completed','failed')),
              attempts INTEGER NOT NULL DEFAULT 0, lease_token TEXT, lease_until REAL,
              not_before REAL NOT NULL, created_at REAL NOT NULL, started_at REAL,
              finished_at REAL, result_json TEXT, error_code TEXT,
              UNIQUE(owner,idempotency_key),
              CHECK((state='completed')=(result_json IS NOT NULL)),
              CHECK((state IN ('completed','failed'))=(finished_at IS NOT NULL)));
            CREATE INDEX IF NOT EXISTS pending_assessments ON assessments(state,not_before,created_at);
            CREATE TRIGGER IF NOT EXISTS immutable_assessment BEFORE UPDATE ON assessments
            WHEN OLD.state IN ('completed','failed') OR
              NEW.id != OLD.id OR NEW.owner != OLD.owner OR
              NEW.request_hash != OLD.request_hash OR NEW.request_json != OLD.request_json OR
              NEW.created_at != OLD.created_at OR NEW.idempotency_key != OLD.idempotency_key
            BEGIN SELECT RAISE(ABORT,'immutable assessment'); END;
            """)

    @contextmanager
    def connection(self, *, write=False):
        db = sqlite3.connect(self.database, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    def asset(self, owner, asset_id):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM assets WHERE owner=? AND id=?", (owner, asset_id)
            ).fetchone()
        if row is None:
            raise NotFound("asset not found")
        return dict(row)

    def add_asset(self, owner, sha256, size_bytes, path):
        with self.connection(write=True) as db:
            db.execute(
                "INSERT OR IGNORE INTO assets VALUES(?,?,?,?,?,?)",
                (uuid.uuid4().hex, owner, sha256, size_bytes, str(path), self.clock()),
            )
            return dict(
                db.execute(
                    "SELECT * FROM assets WHERE owner=? AND sha256=?", (owner, sha256)
                ).fetchone()
            )

    def submit(self, owner, key, request, *, max_pending=1000):
        # Signed URLs locate bytes; their expiry/signature is not input identity.
        identity = dict(request)
        if "media" in identity:
            identity["media"] = {
                k: v for k, v in identity["media"].items() if k != "url"
            }
        digest = hashlib.sha256(canonical(identity).encode()).hexdigest()
        now = self.clock()
        with self.connection(write=True) as db:
            existing = db.execute(
                "SELECT * FROM assessments WHERE owner=? AND idempotency_key=?",
                (owner, key),
            ).fetchone()
            if existing:
                if existing["request_hash"] != digest:
                    raise Conflict("idempotency key has a different input")
                return self.decode(existing)
            pending = db.execute(
                "SELECT count(*) FROM assessments WHERE state IN ('queued','running')"
            ).fetchone()[0]
            if pending >= max_pending:
                raise Capacity("assessment queue is full")
            job_id = uuid.uuid4().hex
            db.execute(
                """INSERT INTO assessments(id,owner,idempotency_key,request_hash,request_json,state,
                         not_before,created_at) VALUES(?,?,?,?,?,'queued',?,?)""",
                (job_id, owner, key, digest, canonical(request), now, now),
            )
            return self.decode(
                db.execute("SELECT * FROM assessments WHERE id=?", (job_id,)).fetchone()
            )

    def get(self, owner, job_id):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM assessments WHERE owner=? AND id=?", (owner, job_id)
            ).fetchone()
        if row is None:
            raise NotFound("assessment not found")
        return self.decode(row)

    @staticmethod
    def decode(row):
        result = dict(row)
        result["request"] = json.loads(result.pop("request_json"))
        profile = result.pop("result_json")
        result["profile"] = json.loads(profile) if profile is not None else None
        return result

    def claim(self, *, lease_seconds=300):
        now = self.clock()
        with self.connection(write=True) as db:
            db.execute(
                """UPDATE assessments SET state='failed',error_code='lease_exhausted',finished_at=?,
                        lease_token=NULL,lease_until=NULL WHERE state='running' AND lease_until<=? AND attempts>=3""",
                (now, now),
            )
            row = db.execute(
                """SELECT id FROM assessments WHERE attempts<3 AND not_before<=? AND
                              (state='queued' OR (state='running' AND lease_until<=?)) ORDER BY created_at,id LIMIT 1""",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                """UPDATE assessments SET state='running',attempts=attempts+1,lease_token=?,lease_until=?,
                        started_at=COALESCE(started_at,?) WHERE id=?""",
                (uuid.uuid4().hex, now + lease_seconds, now, row["id"]),
            )
            return self.decode(
                db.execute(
                    "SELECT * FROM assessments WHERE id=?", (row["id"],)
                ).fetchone()
            )

    def finish(self, job, *, profile=None, error_code=None, retry=False):
        now = self.clock()
        state = (
            "completed"
            if profile is not None
            else "queued"
            if retry and job["attempts"] < 3
            else "failed"
        )
        with self.connection(write=True) as db:
            changed = db.execute(
                """UPDATE assessments SET state=?,result_json=?,error_code=?,finished_at=?,
                not_before=?,lease_token=NULL,lease_until=NULL WHERE id=? AND state='running' AND lease_token=? AND lease_until>?""",
                (
                    state,
                    canonical(profile) if profile is not None else None,
                    error_code,
                    None if state == "queued" else now,
                    now + min(30, job["attempts"] * 2),
                    job["id"],
                    job["lease_token"],
                    now,
                ),
            ).rowcount
            if changed != 1:
                raise LeaseLost("worker lease has expired or been replaced")

    def reap(self, retention_seconds: float) -> dict:
        """Delete expired terminal jobs and unreferenced expired asset blobs."""
        if not math.isfinite(retention_seconds) or retention_seconds <= 0:
            raise ValueError("retention_seconds must be a positive finite number")
        cutoff = float(self.clock()) - float(retention_seconds)
        expired_paths: list[str] = []
        with self.connection(write=True) as db:
            db.execute("UPDATE retention_state SET reap_cutoff=? WHERE id=1", (cutoff,))
            try:
                reaped_jobs = db.execute(
                    """DELETE FROM assessments
                       WHERE state IN ('completed','failed')
                         AND COALESCE(finished_at, created_at) <= ?""",
                    (cutoff,),
                ).rowcount
                candidates = db.execute(
                    """SELECT id, path FROM assets
                       WHERE created_at <= ?
                         AND NOT EXISTS (
                           SELECT 1 FROM assessments a
                           WHERE a.owner = assets.owner
                             AND (
                               json_extract(a.request_json, '$.asset_id') = assets.id
                               OR json_extract(a.request_json, '$.sha256') = assets.sha256
                               OR json_extract(a.request_json, '$.media.sha256') = assets.sha256
                             )
                         )""",
                    (cutoff,),
                ).fetchall()
                for row in candidates:
                    db.execute("DELETE FROM assets WHERE id=?", (row["id"],))
                    expired_paths.append(row["path"])
            finally:
                db.execute("UPDATE retention_state SET reap_cutoff=NULL WHERE id=1")

        for raw_path in expired_paths:
            try:
                target = Path(raw_path).resolve()
                if self.root in target.parents:
                    target.unlink(missing_ok=True)
            except OSError:
                pass

        with self._reap_lock:
            self.reaped_assessments += reaped_jobs
            self.reaped_assets += len(expired_paths)
        return {
            "reaped_assessments": reaped_jobs,
            "reaped_assets": len(expired_paths),
        }

    def statistics(self):
        with self.connection() as db:
            states = {
                r[0]: r[1]
                for r in db.execute(
                    "SELECT state,count(*) FROM assessments GROUP BY state"
                )
            }
            completed = db.execute(
                "SELECT count(*),COALESCE(sum(finished_at-started_at),0) FROM assessments WHERE state='completed'"
            ).fetchone()
        with self._reap_lock:
            reaped_jobs = self.reaped_assessments
            reaped_assets = self.reaped_assets
        return {
            "states": states,
            "completed_count": completed[0],
            "processing_seconds_sum": completed[1],
            "reaped_assessments_total": reaped_jobs,
            "reaped_assets_total": reaped_assets,
        }
