"""Telemetry store for prompt-injection honeypot.

Two backends, written in tandem:

1. SQLite — for analytics queries (top attackers, counts by tag, hourly
   heatmaps, etc.) and for the dashboard.
2. JSONL — append-only file for offline forensics / shipping to a SIEM.

The two are written atomically per record: the SQLite insert commits, then
the JSONL append happens. If the JSONL write fails, the SQLite row is still
present (we don't want to lose a captured attack because a disk is full on
the secondary store); the JSONL write is idempotent on a single line so
re-running replay isn't catastrophic.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from honeypot.classifier import Severity


# ---------------------------------------------------------------------------
# Record type
# ---------------------------------------------------------------------------


@dataclass
class TelemetryRecord:
    """One captured attempt at the honeypot."""

    ts: str
    src_ip: str
    user_agent: str
    endpoint: str
    user: str
    message: str
    tags: list[str]
    severity: Severity
    matched_patterns: list[str]
    response_status: int
    response_excerpt: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = int(self.severity)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TelemetryRecord":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        return cls(**d)


def new_record(
    *,
    src_ip: str,
    user_agent: str,
    endpoint: str,
    user: str,
    message: str,
    tags: list[str],
    severity: Severity,
    matched_patterns: list[str],
    response_status: int,
    response_excerpt: str,
) -> TelemetryRecord:
    """Build a TelemetryRecord with the current UTC timestamp."""
    return TelemetryRecord(
        ts=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        src_ip=src_ip,
        user_agent=user_agent,
        endpoint=endpoint,
        user=user,
        message=message,
        tags=list(tags),
        severity=severity,
        matched_patterns=list(matched_patterns),
        response_status=response_status,
        response_excerpt=response_excerpt,
    )


# ---------------------------------------------------------------------------
# JSONL writer (also importable standalone)
# ---------------------------------------------------------------------------


def write_jsonl(path: Path, records: TelemetryRecord | Iterable[TelemetryRecord]) -> None:
    """Append one or more records to a JSONL file.

    The file is created if missing. Each line is a complete JSON object.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(records, TelemetryRecord):
        records = [records]
    with path.open("a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r.to_dict(), ensure_ascii=False))
            f.write("\n")


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    user_agent TEXT,
    endpoint TEXT,
    user TEXT,
    message TEXT,
    tags TEXT,           -- JSON array of strings
    severity INTEGER,    -- 0 NONE, 1 LOW, 2 MEDIUM, 3 HIGH
    matched_patterns TEXT,-- JSON array of strings
    response_status INTEGER,
    response_excerpt TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


class Telemetry:
    """Dual SQLite + JSONL telemetry store.

    Thread-safe — uses a single internal lock so concurrent requests from
    the FastAPI worker pool don't interleave their writes.
    """

    def __init__(self, db_path: Path, jsonl_path: Path | None = None) -> None:
        self.db_path = Path(db_path)
        self.jsonl_path = Path(jsonl_path) if jsonl_path else None
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    # ---- low-level -----------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)

    # ---- writes -------------------------------------------------------

    def record(self, r: TelemetryRecord) -> None:
        """Persist `r` to both backends atomically (best effort)."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO events (
                        ts, src_ip, user_agent, endpoint, user, message,
                        tags, severity, matched_patterns,
                        response_status, response_excerpt
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        r.ts,
                        r.src_ip,
                        r.user_agent,
                        r.endpoint,
                        r.user,
                        r.message,
                        json.dumps(r.tags, ensure_ascii=False),
                        int(r.severity),
                        json.dumps(r.matched_patterns, ensure_ascii=False),
                        r.response_status,
                        r.response_excerpt,
                    ),
                )
            if self.jsonl_path is not None:
                write_jsonl(self.jsonl_path, r)

    # ---- reads --------------------------------------------------------

    def fetch_all(
        self,
        severity_at_least: Severity | None = None,
        tag: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM events"
        clauses: list[str] = []
        params: list[Any] = []
        if severity_at_least is not None:
            clauses.append("severity >= ?")
            params.append(int(severity_at_least))
        if tag is not None:
            clauses.append("tags LIKE ?")
            params.append(f'%"{tag}"%')
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(row) for row in rows]

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    def count_by_tag(self) -> dict[str, int]:
        """Return a tag -> count map.

        Implemented in Python because the tags column is JSON-encoded text,
        not a normalised table — a join would be slower for the row counts
        we expect (thousands to low millions).
        """
        out: dict[str, int] = {}
        with self._connect() as conn:
            for row in conn.execute("SELECT tags FROM events"):
                try:
                    tags = json.loads(row["tags"])
                except (json.JSONDecodeError, TypeError):
                    continue
                for t in tags:
                    out[t] = out.get(t, 0) + 1
        return out

    def top_attackers(self, limit: int = 10) -> list[dict[str, Any]]:
        sql = """
            SELECT src_ip, COUNT(*) AS count
            FROM events
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT ?
        """
        with self._connect() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
        return [{"src_ip": r["src_ip"], "count": r["count"]} for r in rows]

    def hourly_counts(self, hours: int = 24) -> list[dict[str, Any]]:
        """Return event count per hour for the last `hours` hours."""
        sql = """
            SELECT substr(ts, 1, 13) AS hour, COUNT(*) AS count
            FROM events
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT ?
        """
        with self._connect() as conn:
            rows = conn.execute(sql, (hours,)).fetchall()
        # reverse to chronological order for plotting
        return [{"hour": r["hour"], "count": r["count"]} for r in rows][::-1]


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["tags"] = json.loads(d["tags"])
    except (json.JSONDecodeError, TypeError, KeyError):
        d["tags"] = []
    try:
        d["matched_patterns"] = json.loads(d["matched_patterns"])
    except (json.JSONDecodeError, TypeError, KeyError):
        d["matched_patterns"] = []
    try:
        d["severity"] = Severity(d["severity"])
    except (KeyError, ValueError):
        d["severity"] = Severity.NONE
    return d