import sqlite3
import time
import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class RuleStats:
    rule_id: str
    fires_total: int = 0
    blocks_total: int = 0
    warns_total: int = 0
    allows_total: int = 0
    trend: str = "SILENT"
    block_rate: float = 0.0


class ObservationGraph:

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._ensure_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    agent_name TEXT,
                    ingested_at REAL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    rule_id TEXT,
                    rule_name TEXT,
                    verdict TEXT,
                    surface TEXT,
                    tier INTEGER DEFAULT 0,
                    cmd TEXT DEFAULT '',
                    url TEXT DEFAULT '',
                    latency_ms REAL DEFAULT 0,
                    timestamp REAL
                );
                CREATE TABLE IF NOT EXISTS agentdef_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    path TEXT,
                    violation_type TEXT,
                    original_hash TEXT,
                    current_hash TEXT,
                    detected_at REAL,
                    semantic_risk TEXT DEFAULT 'LOW',
                    semantic_score REAL DEFAULT 0.0
                );
                CREATE TABLE IF NOT EXISTS spawn_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    parent_session_id TEXT,
                    child_session_id TEXT,
                    agent_name TEXT,
                    cmd TEXT,
                    spawned_at REAL,
                    policy_propagated INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS reward_signals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    rule_id TEXT,
                    verdict TEXT,
                    aiglos_verdict TEXT,
                    aiglos_rule_id TEXT,
                    claimed_reward REAL,
                    adjusted_reward REAL,
                    override_applied INTEGER DEFAULT 0,
                    semantic_risk TEXT DEFAULT 'LOW',
                    semantic_score REAL DEFAULT 0.0,
                    feedback_preview TEXT DEFAULT '',
                    timestamp REAL
                );
            """)

    def ingest(self, artifact) -> str:
        """Pull events, agentdef violations, and spawn history out of a SessionArtifact."""
        extra = artifact.extra
        sid = extra.get("session_identity", {}).get("session_id", "unknown")
        with self._conn() as conn:
            existing = conn.execute("SELECT 1 FROM sessions WHERE session_id=?", (sid,)).fetchone()
            if existing:
                return sid
            conn.execute(
                "INSERT INTO sessions (session_id, agent_name, ingested_at) VALUES (?,?,?)",
                (sid, artifact.agent_name, time.time()),
            )
            for ev in extra.get("http_events", []) + extra.get("subproc_events", []):
                conn.execute(
                    "INSERT INTO events (session_id, rule_id, rule_name, verdict, surface, tier, cmd, url, latency_ms, timestamp) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (sid, ev.get("rule_id", ""), ev.get("rule_name", ""), ev.get("verdict", ""),
                     ev.get("surface", ""), ev.get("tier", 0), ev.get("cmd", ""), ev.get("url", ""),
                     ev.get("latency_ms", 0), ev.get("timestamp", time.time())),
                )
            for v in extra.get("agentdef_violations", []):
                conn.execute(
                    "INSERT INTO agentdef_observations (session_id, path, violation_type, original_hash, current_hash, detected_at, semantic_risk, semantic_score) VALUES (?,?,?,?,?,?,?,?)",
                    (sid, v.get("path", ""), v.get("violation", ""), v.get("original_hash", ""),
                     v.get("current_hash", ""), v.get("detected_at", time.time()),
                     v.get("semantic_risk", "LOW"), v.get("semantic_score", 0.0)),
                )
            multi = extra.get("multi_agent", {})
            for sp in multi.get("spawns", []):
                conn.execute(
                    "INSERT INTO spawn_events (session_id, parent_session_id, child_session_id, agent_name, cmd, spawned_at, policy_propagated) VALUES (?,?,?,?,?,?,?)",
                    (sid, sp.get("parent_session_id", ""), sp.get("child_session_id", ""),
                     sp.get("agent_name", ""), sp.get("cmd", ""), sp.get("spawned_at", time.time()),
                     1 if sp.get("policy_propagated") else 0),
                )
        return sid

    def session_count(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    def rule_stats(self, rule_id: str) -> RuleStats:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT verdict FROM events WHERE rule_id=?", (rule_id,)
            ).fetchall()
        if not rows:
            return RuleStats(rule_id=rule_id, trend="SILENT")
        blocks = sum(1 for r in rows if r["verdict"] == "BLOCK")
        warns = sum(1 for r in rows if r["verdict"] == "WARN")
        allows = sum(1 for r in rows if r["verdict"] == "ALLOW")
        total = len(rows)
        br = blocks / total if total else 0.0
        trend = "RISING" if blocks > warns else ("STABLE" if total < 5 else "FALLING")
        return RuleStats(
            rule_id=rule_id, fires_total=total, blocks_total=blocks,
            warns_total=warns, allows_total=allows, trend=trend, block_rate=br,
        )

    def all_rule_stats(self) -> List[RuleStats]:
        with self._conn() as conn:
            rule_ids = [r[0] for r in conn.execute(
                "SELECT DISTINCT rule_id FROM events WHERE rule_id != ''"
            ).fetchall()]
        stats = [self.rule_stats(rid) for rid in rule_ids]
        stats.sort(key=lambda s: s.fires_total, reverse=True)
        return stats

    def spawn_history(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM spawn_events ORDER BY spawned_at").fetchall()
        return [dict(r) for r in rows]

    def recent_sessions(self, n: int = 5) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY ingested_at DESC LIMIT ?", (n,)
            ).fetchall()
        return [dict(r) for r in rows]

    def summary(self) -> Dict:
        with self._conn() as conn:
            sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        top = self.all_rule_stats()[:5]
        return {
            "sessions": sessions,
            "top_rules": [{"rule_id": s.rule_id, "fires": s.fires_total} for s in top],
        }

    def events_for_rule(self, rule_id: str) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE rule_id=?", (rule_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def ingest_reward_signal(self, signal, session_id: str):
        if hasattr(signal, "to_dict"):
            d = signal.to_dict()
        elif isinstance(signal, dict):
            d = signal
        else:
            d = dict(signal)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO reward_signals (session_id, rule_id, verdict, aiglos_verdict, aiglos_rule_id, claimed_reward, adjusted_reward, override_applied, semantic_risk, semantic_score, feedback_preview, timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (session_id, d.get("rule_id", ""), d.get("verdict", ""),
                 d.get("aiglos_verdict", ""), d.get("aiglos_rule_id", ""),
                 d.get("claimed_reward", 0), d.get("adjusted_reward", 0),
                 1 if d.get("override_applied") else 0,
                 d.get("semantic_risk", "LOW"), d.get("semantic_score", 0.0),
                 d.get("feedback_preview", ""), d.get("timestamp", time.time())),
            )

    def reward_signal_stats(self, session_id: str = None) -> Dict:
        with self._conn() as conn:
            if session_id:
                rows = conn.execute(
                    "SELECT * FROM reward_signals WHERE session_id=?", (session_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM reward_signals").fetchall()
        total = len(rows)
        quarantined = sum(1 for r in rows if r["verdict"] == "QUARANTINE")
        t39 = sum(1 for r in rows if r["rule_id"] == "T39")
        return {"total_signals": total, "quarantined": quarantined, "t39_fires": t39}

    def reward_drift_data(self) -> Dict:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM reward_signals ORDER BY timestamp"
            ).fetchall()
        rows = [dict(r) for r in rows]
        mid = len(rows) // 2 if rows else 0
        return {"recent": rows[mid:], "baseline": rows[:mid]}
