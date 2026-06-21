# Architecture

## Data flow

```
                ┌───────────────────────────────┐
   attacker ──▶ │   /v1/support  (FastAPI)      │
                │                                │
                │   1. classify(message)         │
                │   2. pick reply (benign|       │
                │      canned_refusal)           │
                │   3. screen reply for leaks    │
                │   4. telemetry.record(...)     │
                └───────────────┬────────────────┘
                                │
                  ┌─────────────┴─────────────┐
                  ▼                           ▼
        ┌──────────────────┐        ┌──────────────────┐
        │  SQLite (WAL)    │        │   JSONL append   │
        │  ./data/         │        │  ./data/         │
        │  honeypot.db     │        │  honeypot.jsonl  │
        └────────┬─────────┘        └──────────────────┘
                 │
                 ▼
        ┌──────────────────┐
        │   Dashboard      │
        │   (Streamlit)    │
        │   charts + table │
        │   + CSV export   │
        └──────────────────┘
```

## Components

| Module                         | Role                                                     |
|--------------------------------|----------------------------------------------------------|
| `honeypot/classifier.py`       | Pure-regex injection pattern matcher + severity bucketing |
| `honeypot/telemetry.py`        | SQLite (WAL) + JSONL dual-write store + analytics helpers |
| `honeypot/server.py`           | FastAPI app with the fake LLM endpoint                   |
| `honeypot/dashboard.py`        | Streamlit operator dashboard                             |

## Failure modes and guarantees

| Failure                           | What happens                                                |
|-----------------------------------|-------------------------------------------------------------|
| Classifier misses an attack       | The response is still a benign-helpful reply — never a leak. The honeypot just *fails to log* the attack class. Downstream consumers can re-run classification later over the raw message column. |
| Classifier false-positives        | The user gets a canned refusal. Annoying, not destructive. |
| Telemetry SQLite write fails      | The endpoint returns 500. The user sees a server error, NOT a leaked secret. |
| Telemetry JSONL write fails       | The SQLite row is still persisted; JSONL write logs to stderr but does not affect the user. |
| Reply screening fails             | The endpoint returns 500 — never the offending reply.       |
| Attacker overwhelms the server    | Uvicorn defaults are conservative; in production put it behind a rate limiter (e.g. nginx limit_req, fail2ban, Cloudflare). |

## Why pattern matching, not a model?

The classifier is intentionally a static rule set, not a model call:

- **Deterministic.** Same input → same output. Easier to audit, easier to
  reproduce bugs.
- **Inspectable.** Every rule has a name and a regex; a sample match can
  be replayed through pytest.
- **Cheap.** Microseconds per prompt. No GPU, no API call, no per-token cost.
- **No recursion.** A classifier that calls an LLM creates a new prompt-
  injection surface. Static regex breaks that loop.

If you want to layer a model on top (e.g. for low-confidence escalation),
do it in a separate process with its own audit log, never inside the
hot path of `/v1/support`.

## Schema

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,            -- ISO-8601 UTC
    src_ip TEXT NOT NULL,        -- client IP (X-Forwarded-For honoured)
    user_agent TEXT,             -- raw UA header
    endpoint TEXT,               -- path the request hit
    user TEXT,                   -- user-supplied identifier
    message TEXT,                -- the raw prompt
    tags TEXT,                   -- JSON array of attack tags
    severity INTEGER,            -- 0 NONE / 1 LOW / 2 MEDIUM / 3 HIGH
    matched_patterns TEXT,       -- JSON array of regex pattern strings
    response_status INTEGER,
    response_excerpt TEXT        -- first 200 chars of the reply
);
CREATE INDEX idx_events_src_ip ON events(src_ip);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_ts ON events(ts);
```

## Threat model

**Out of scope** (this is a portfolio honeypot, not production):

- Distributed volumetric attacks — use a real WAF / rate limiter upstream.
- TLS termination — terminate at a reverse proxy (Caddy, nginx).
- Auth on the operator endpoints (`/v1/stats`, dashboard) — bind to
  localhost or front with basic auth.
- Multi-tenant telemetry — one DB per deployment is fine.

**In scope** (the actual point of the project):

- Detecting single-prompt injection attempts.
- Recording enough metadata for retrospective analysis.
- Demonstrating the right architectural shape: classify → log → refuse.