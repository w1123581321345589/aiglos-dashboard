"""
aiglos.adaptive.observation
============================
Phase 1: Observation graph — SQLite-backed storage of session artifacts,
rule firing history, and agent definition snapshots.

Everything the adaptive layer needs as input is already in the v0.3.0 session
artifact. This module structures that output into a queryable graph keyed by
rule, agent, command pattern, and outcome.

Schema:
  rules         — one row per rule family (T01-T38)
  sessions      — one row per session
  events        — one row per inspected action (MCP, HTTP, subprocess)
  agentdef_obs  — one row per agent definition observation
  spawn_events  — one row per T38 spawn
  amendments    — one row per proposed/applied rule amendment (Phase 4)

Usage:
    from aiglos.adaptive.observation import ObservationGraph

    graph = ObservationGraph()            # defaults to ~/.aiglos/observations.db
    graph.ingest(artifact)                # call after aiglos.close()

    stats = graph.rule_stats("T37")
    # { "fires": 12, "blocks": 9, "warns": 2, "allows": 1,
    #   "override_rate": 0.08, "trend": "STABLE" }
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("aiglos.adaptive.observation")

DEFAULT_DB_PATH = Path.home() / ".aiglos" / "observations.db"

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    agent_name      TEXT NOT NULL DEFAULT '',
    aiglos_version  TEXT NOT NULL DEFAULT '',
    started_at      REAL NOT NULL DEFAULT 0,
    closed_at       REAL NOT NULL DEFAULT 0,
    total_events    INTEGER NOT NULL DEFAULT 0,
    blocked_events  INTEGER NOT NULL DEFAULT 0,
    raw_artifact    TEXT,          -- JSON blob of full artifact
    ingested_at     REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    surface         TEXT NOT NULL,  -- 'mcp' | 'http' | 'subprocess'
    rule_id         TEXT NOT NULL DEFAULT 'none',
    rule_name       TEXT NOT NULL DEFAULT '',
    verdict         TEXT NOT NULL,  -- ALLOW | WARN | BLOCK | PAUSE
    tier            INTEGER,        -- 1 | 2 | 3 (subprocess only)
    cmd_hash        TEXT,           -- sha256[:16] of cmd/url (no raw data stored)
    cmd_preview     TEXT,           -- first 80 chars of cmd/url (for debugging)
    latency_ms      REAL,
    timestamp       REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rule_stats_cache (
    rule_id         TEXT PRIMARY KEY,
    fires_total     INTEGER NOT NULL DEFAULT 0,
    blocks_total    INTEGER NOT NULL DEFAULT 0,
    warns_total     INTEGER NOT NULL DEFAULT 0,
    allows_total    INTEGER NOT NULL DEFAULT 0,
    sessions_seen   INTEGER NOT NULL DEFAULT 0,
    last_seen       REAL NOT NULL DEFAULT 0,
    last_updated    REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agentdef_observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    path_hash       TEXT NOT NULL,   -- sha256[:16] of path
    path_preview    TEXT NOT NULL,   -- last 60 chars of path
    violation_type  TEXT,            -- MODIFIED | ADDED | DELETED | NULL (clean)
    semantic_risk   TEXT,            -- HIGH | MEDIUM | LOW | NULL
    semantic_score  REAL,            -- 0.0-1.0 divergence score
    original_hash   TEXT,
    current_hash    TEXT,
    observed_at     REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS spawn_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    parent_id       TEXT NOT NULL,
    child_id        TEXT NOT NULL,
    agent_name      TEXT NOT NULL DEFAULT '',
    cmd_preview     TEXT,
    policy_propagated INTEGER NOT NULL DEFAULT 0,
    spawned_at      REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_rule    ON events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp);
"""


# ── RuleStats dataclass ───────────────────────────────────────────────────────

@dataclass
class RuleStats:
    rule_id:      str
    fires_total:  int   = 0
    blocks_total: int   = 0
    warns_total:  int   = 0
    allows_total: int   = 0
    sessions_seen: int  = 0
    last_seen:    float = 0.0

    @property
    def block_rate(self) -> float:
        return self.blocks_total / self.fires_total if self.fires_total else 0.0

    @property
    def override_rate(self) -> float:
        """Rate at which blocks are followed by manual allow-list addition."""
        # Approximated as warns_total / fires_total for now;
        # Phase 4 amendment engine tracks true override rate.
        return self.warns_total / self.fires_total if self.fires_total else 0.0

    @property
    def trend(self) -> str:
        """Coarse trend based on sessions_seen vs fires_total."""
        if self.fires_total == 0:
            return "SILENT"
        avg = self.fires_total / max(self.sessions_seen, 1)
        if avg < 0.1:
            return "RARE"
        if avg < 1.0:
            return "OCCASIONAL"
        if avg < 5.0:
            return "ACTIVE"
        return "HIGH_VOLUME"

    def to_dict(self) -> dict:
        return {
            "rule_id":      self.rule_id,
            "fires_total":  self.fires_total,
            "blocks_total": self.blocks_total,
            "warns_total":  self.warns_total,
            "allows_total": self.allows_total,
            "sessions_seen": self.sessions_seen,
            "last_seen":    self.last_seen,
            "block_rate":   round(self.block_rate, 4),
            "override_rate": round(self.override_rate, 4),
            "trend":        self.trend,
        }


# ── ObservationGraph ──────────────────────────────────────────────────────────

class ObservationGraph:
    """
    SQLite-backed observation graph for Aiglos session artifacts.

    Thread-safe. Uses WAL mode for concurrent reads.
    The database is created automatically on first use.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path or os.environ.get("AIGLOS_OBS_DB", str(DEFAULT_DB_PATH)))
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self._db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    # ── Ingestion ──────────────────────────────────────────────────────────────

    def ingest(self, artifact: Any) -> str:
        """
        Ingest a SessionArtifact into the observation graph.

        Returns the session_id stored.
        Idempotent: ingesting the same artifact twice is a no-op.
        """
        session_id = self._extract_session_id(artifact)
        if self._session_exists(session_id):
            log.debug("[ObsGraph] Session %s already ingested, skipping.", session_id[:12])
            return session_id

        extra      = getattr(artifact, "extra", {}) or {}
        agent_name = getattr(artifact, "agent_name", "")
        version    = extra.get("aiglos_version", "")
        now        = time.time()

        http_events    = extra.get("http_events", [])
        subproc_events = extra.get("subproc_events", [])
        all_events     = self._normalise_events(http_events, "http") + \
                         self._normalise_events(subproc_events, "subprocess")
        blocked        = sum(1 for e in all_events if e["verdict"] == "BLOCK")

        agentdef_violations = extra.get("agentdef_violations", [])
        multi_agent         = extra.get("multi_agent", {})
        identity            = extra.get("session_identity", {})
        started_at          = identity.get("created_at", now)

        try:
            raw = json.dumps({
                "session_id": session_id,
                "agent_name": agent_name,
                "version":    version,
            })
        except Exception:
            raw = "{}"

        with self._conn() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO sessions
                    (session_id, agent_name, aiglos_version, started_at,
                     closed_at, total_events, blocked_events, raw_artifact, ingested_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (session_id, agent_name, version, started_at,
                  now, len(all_events), blocked, raw, now))

            for ev in all_events:
                conn.execute("""
                    INSERT INTO events
                        (session_id, surface, rule_id, rule_name, verdict,
                         tier, cmd_hash, cmd_preview, latency_ms, timestamp)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                """, (session_id, ev["surface"], ev["rule_id"], ev["rule_name"],
                      ev["verdict"], ev.get("tier"), ev["cmd_hash"],
                      ev["cmd_preview"], ev.get("latency_ms"), ev.get("timestamp", now)))

            for v in agentdef_violations:
                path = v.get("path", "")
                conn.execute("""
                    INSERT INTO agentdef_observations
                        (session_id, path_hash, path_preview, violation_type,
                         semantic_risk, semantic_score, original_hash, current_hash, observed_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (session_id,
                      hashlib.sha256(path.encode()).hexdigest()[:16],
                      path[-60:],
                      v.get("violation"),
                      v.get("semantic_risk"),
                      v.get("semantic_score"),
                      v.get("original_hash", ""),
                      v.get("current_hash", ""),
                      v.get("detected_at", now)))

            for spawn in multi_agent.get("spawns", []):
                conn.execute("""
                    INSERT INTO spawn_events
                        (session_id, parent_id, child_id, agent_name,
                         cmd_preview, policy_propagated, spawned_at)
                    VALUES (?,?,?,?,?,?,?)
                """, (session_id,
                      spawn.get("parent_session_id", ""),
                      spawn.get("child_session_id", ""),
                      spawn.get("agent_name", ""),
                      (spawn.get("cmd", "") or "")[:80],
                      1 if spawn.get("policy_propagated") else 0,
                      spawn.get("spawned_at", now)))

        self._update_rule_stats_cache(session_id)
        log.info("[ObsGraph] Ingested session %s: %d events, %d blocked.",
                 session_id[:12], len(all_events), blocked)
        return session_id

    def _normalise_events(self, events: list, surface: str) -> list:
        out = []
        for ev in events:
            cmd = ev.get("cmd") or ev.get("url") or ""
            out.append({
                "surface":    surface,
                "rule_id":    ev.get("rule_id", "none"),
                "rule_name":  ev.get("rule_name", ""),
                "verdict":    ev.get("verdict", "ALLOW"),
                "tier":       ev.get("tier"),
                "cmd_hash":   hashlib.sha256(cmd.encode()).hexdigest()[:16],
                "cmd_preview": cmd[:80],
                "latency_ms": ev.get("latency_ms"),
                "timestamp":  ev.get("timestamp", time.time()),
            })
        return out

    def _extract_session_id(self, artifact: Any) -> str:
        extra = getattr(artifact, "extra", {}) or {}
        identity = extra.get("session_identity", {})
        sid = identity.get("session_id")
        if sid:
            return sid
        # Fallback: hash the artifact object id + timestamp
        return hashlib.sha256(f"{id(artifact)}{time.time()}".encode()).hexdigest()[:32]

    def _session_exists(self, session_id: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM sessions WHERE session_id=?", (session_id,)
            ).fetchone()
        return row is not None

    def _update_rule_stats_cache(self, session_id: str) -> None:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT rule_id,
                       COUNT(*) as fires,
                       SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) as blocks,
                       SUM(CASE WHEN verdict='WARN'  THEN 1 ELSE 0 END) as warns,
                       SUM(CASE WHEN verdict='ALLOW' THEN 1 ELSE 0 END) as allows,
                       MAX(timestamp) as last_seen
                FROM events WHERE session_id=? AND rule_id != 'none'
                GROUP BY rule_id
            """, (session_id,)).fetchall()

            for row in rows:
                conn.execute("""
                    INSERT INTO rule_stats_cache
                        (rule_id, fires_total, blocks_total, warns_total,
                         allows_total, sessions_seen, last_seen, last_updated)
                    VALUES (?,?,?,?,?,1,?,?)
                    ON CONFLICT(rule_id) DO UPDATE SET
                        fires_total  = fires_total  + excluded.fires_total,
                        blocks_total = blocks_total + excluded.blocks_total,
                        warns_total  = warns_total  + excluded.warns_total,
                        allows_total = allows_total + excluded.allows_total,
                        sessions_seen = sessions_seen + 1,
                        last_seen    = MAX(last_seen, excluded.last_seen),
                        last_updated = excluded.last_updated
                """, (row["rule_id"], row["fires"], row["blocks"],
                      row["warns"], row["allows"], row["last_seen"], time.time()))

    # ── Query API ──────────────────────────────────────────────────────────────

    def rule_stats(self, rule_id: str) -> RuleStats:
        """Return firing statistics for a specific rule."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM rule_stats_cache WHERE rule_id=?", (rule_id,)
            ).fetchone()
        if row is None:
            return RuleStats(rule_id=rule_id)
        return RuleStats(
            rule_id=rule_id,
            fires_total=row["fires_total"],
            blocks_total=row["blocks_total"],
            warns_total=row["warns_total"],
            allows_total=row["allows_total"],
            sessions_seen=row["sessions_seen"],
            last_seen=row["last_seen"],
        )

    def all_rule_stats(self) -> List[RuleStats]:
        """Return stats for all rules that have fired."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM rule_stats_cache ORDER BY fires_total DESC"
            ).fetchall()
        return [RuleStats(
            rule_id=r["rule_id"],
            fires_total=r["fires_total"],
            blocks_total=r["blocks_total"],
            warns_total=r["warns_total"],
            allows_total=r["allows_total"],
            sessions_seen=r["sessions_seen"],
            last_seen=r["last_seen"],
        ) for r in rows]

    def session_count(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    def recent_sessions(self, n: int = 10) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT session_id, agent_name, total_events, blocked_events, closed_at "
                "FROM sessions ORDER BY closed_at DESC LIMIT ?", (n,)
            ).fetchall()
        return [dict(r) for r in rows]

    def events_for_rule(self, rule_id: str, limit: int = 100) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT e.*, s.agent_name FROM events e
                JOIN sessions s ON e.session_id = s.session_id
                WHERE e.rule_id=? ORDER BY e.timestamp DESC LIMIT ?
            """, (rule_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def agentdef_violations_for_path(self, path_hash: str) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM agentdef_observations WHERE path_hash=? "
                "ORDER BY observed_at DESC", (path_hash,)
            ).fetchall()
        return [dict(r) for r in rows]

    def spawn_history(self, agent_name: Optional[str] = None) -> List[dict]:
        with self._conn() as conn:
            if agent_name:
                rows = conn.execute(
                    "SELECT * FROM spawn_events WHERE agent_name=? "
                    "ORDER BY spawned_at DESC", (agent_name,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM spawn_events ORDER BY spawned_at DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    def summary(self) -> dict:
        """High-level summary across all ingested data."""
        with self._conn() as conn:
            sess = conn.execute(
                "SELECT COUNT(*) as c, SUM(blocked_events) as b FROM sessions"
            ).fetchone()
            top_rules = conn.execute(
                "SELECT rule_id, fires_total FROM rule_stats_cache "
                "ORDER BY fires_total DESC LIMIT 5"
            ).fetchall()
            recent_agentdef = conn.execute(
                "SELECT COUNT(*) FROM agentdef_observations WHERE violation_type IS NOT NULL"
            ).fetchone()[0]
            spawn_count = conn.execute("SELECT COUNT(*) FROM spawn_events").fetchone()[0]
        return {
            "sessions":          sess["c"] or 0,
            "total_blocked":     sess["b"] or 0,
            "top_rules":         [{"rule_id": r["rule_id"], "fires": r["fires_total"]}
                                  for r in top_rules],
            "agentdef_violations": recent_agentdef,
            "spawn_events":      spawn_count,
        }
