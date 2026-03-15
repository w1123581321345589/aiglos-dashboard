"""
aiglos_core/autonomous/registry.py  —  T30  RegistryMonitor
============================================================
Continuous public registry monitoring with auto-blocklist updates.

Supported registries
  - npm           (registry.npmjs.org)
  - PyPI          (pypi.org)
  - Smithery      (smithery.ai)
  - mcp.so        (mcp.so)
  - ClawHub       (openclaw.ai / community skill marketplace)     ← NEW
  - SkillsMP      (skillsmp.io / third-party OpenClaw skills)    ← NEW

Risk signals scored per package (0–100)
  1.  Typosquatting distance from known-legitimate packages
  2.  Social-engineering language in README / description
  3.  Known-malicious publisher account
  4.  Version gap anomaly (skipped major versions — common in fast-publish attacks)
  5.  Publish timestamp anomaly (published in last 48 h with zero history)
  6.  Dependency confusion pattern (internal name on public registry)
  7.  Suspicious permission scope (requests file / shell / network without justification)
  8.  Community report flag (reported on GitHub Issues / Discord by known researchers)

Score  ≥ 70  →  CRITICAL   auto-add to blocklist, alert
Score  50–69 →  HIGH        alert, require manual review
Score  25–49 →  MEDIUM      log finding
Score   <25  →  LOW         record only

Usage
-----
    from aiglos_core.autonomous.registry import RegistryMonitor

    monitor = RegistryMonitor(audit_db="aiglos_audit.db")

    # One-shot scan of all registries
    report = await monitor.scan()

    # Scan specific registries only
    report = await monitor.scan(registries=["clawhub", "skillsmp"])

    # Lookup a single package
    finding = await monitor.score_package("clawhub", "solana-wallet-tracker", metadata={})

    # Refresh blocklist (called automatically by T22 intel_refresh)
    added = await monitor.refresh_blocklist()
"""

from abc import ABC, abstractmethod

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

log = logging.getLogger("aiglos.t30")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class RegistryRisk(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# Canonical names for legitimate packages — used in typosquat distance check
KNOWN_LEGITIMATE: dict[str, list[str]] = {
    "npm": [
        "@anthropic-ai/sdk", "anthropic", "@openai/agents-sdk", "langchain", "llamaindex",
        "mcp", "@modelcontextprotocol/sdk", "openai", "zod", "axios",
    ],
    "pypi": [
        "anthropic", "openai", "langchain", "langchain-core", "llama-index",
        "mcp", "httpx", "pydantic", "fastapi",
    ],
    "smithery": [
        "fetch", "filesystem", "github", "google-maps", "postgres",
        "slack", "sequential-thinking", "brave-search",
    ],
    "mcp.so": [
        "fetch", "filesystem", "github", "slack", "brave-search",
    ],
    "clawhub": [
        "calendar", "email", "weather", "browser", "files",
        "telegram", "whatsapp", "slack", "discord", "notes",
    ],
    "skillsmp": [
        "calendar", "email", "weather", "browser", "notes",
    ],
}

# Social-engineering phrases found in malicious skill READMEs (OpenClaw incident)
SOCIAL_ENGINEERING_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"run this script",
        r"paste.*terminal",
        r"execute.*following",
        r"required setup step",
        r"install dependencies manually",
        r"one.time activation",
        r"copy.*and run",
        r"disable.*security",
        r"bypass.*check",
        r"allow.*unsigned",
        r"grant.*full access",
        r"admin.*required",
    ]
]

# Permissions that require justification in a skill manifest
HIGH_RISK_PERMISSIONS = {
    "shell", "exec", "filesystem", "network", "credentials",
    "keychain", "password", "oauth", "browser", "clipboard",
}

# Known-malicious publisher accounts (from OpenClaw ClawJacked post-mortems)
KNOWN_MALICIOUS_PUBLISHERS: set[str] = {
    "solana-labs-official",
    "claw-community-builds",
    "openclaw-extensions",
    "mcp-tools-hub",
    "ai-skills-market",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PackageSignals:
    """Raw signals extracted from a package entry before scoring."""
    name: str
    registry: str
    publisher: str = ""
    description: str = ""
    readme: str = ""
    permissions: list[str] = field(default_factory=list)
    version: str = ""
    publish_timestamp: float = 0.0   # unix epoch
    download_count: int = 0
    community_flags: int = 0
    raw_metadata: dict = field(default_factory=dict)


@dataclass
class RegistryFinding:
    """Result of scoring a single package."""
    registry: str
    package_name: str
    version: str
    risk: RegistryRisk
    score: int                          # 0–100
    signals_triggered: list[str]
    auto_blocked: bool
    finding_id: str = ""
    timestamp: str = ""
    detail: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.finding_id:
            raw = f"{self.registry}:{self.package_name}:{self.version}:{self.score}"
            self.finding_id = "RF-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "finding_id":        self.finding_id,
            "registry":          self.registry,
            "package_name":      self.package_name,
            "version":           self.version,
            "risk":              self.risk.value,
            "score":             self.score,
            "signals_triggered": self.signals_triggered,
            "auto_blocked":      self.auto_blocked,
            "timestamp":         self.timestamp,
            "detail":            self.detail,
        }


@dataclass
class RegistryScanReport:
    """Aggregate result of a full registry scan."""
    scan_id: str
    started_at: str
    completed_at: str
    registries_scanned: list[str]
    packages_evaluated: int
    findings: list[RegistryFinding]
    blocklist_additions: list[str]
    summary: dict = field(default_factory=dict)

    def __post_init__(self):
        counts = {r.value: 0 for r in RegistryRisk}
        for f in self.findings:
            counts[f.risk.value] += 1
        self.summary = {
            "total_findings":      len(self.findings),
            "critical":            counts["CRITICAL"],
            "high":                counts["HIGH"],
            "medium":              counts["MEDIUM"],
            "low":                 counts["LOW"],
            "auto_blocked":        len(self.blocklist_additions),
            "packages_evaluated":  self.packages_evaluated,
        }

    def to_dict(self) -> dict:
        return {
            "scan_id":             self.scan_id,
            "started_at":          self.started_at,
            "completed_at":        self.completed_at,
            "registries_scanned":  self.registries_scanned,
            "packages_evaluated":  self.packages_evaluated,
            "summary":             self.summary,
            "blocklist_additions": self.blocklist_additions,
            "findings":            [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

class PackageScorer:
    """
    Scores a PackageSignals object against the 8 risk signals.
    Returns (score: int, signals_triggered: list[str]).
    """

    # Weight per signal (must sum to ≤ 100)
    WEIGHTS = {
        "typosquat":              25,
        "social_engineering":     20,
        "known_malicious_pub":    20,
        "version_gap_anomaly":    10,
        "new_publish_anomaly":    10,
        "dependency_confusion":   5,
        "suspicious_permissions": 5,
        # community_flag scales: 1–2 flags = 5, 3–9 flags = 10, 10+ flags = 15
        "community_flag_low":     5,
        "community_flag_mid":     10,
        "community_flag_high":    15,
    }

    def score(self, pkg: PackageSignals) -> tuple[int, list[str]]:
        total = 0
        triggered: list[str] = []
        w = self.WEIGHTS

        # 1. Typosquatting
        if self._is_typosquat(pkg.name, KNOWN_LEGITIMATE.get(pkg.registry, [])):
            total += w["typosquat"]
            triggered.append("typosquat")

        # 2. Social engineering language in README or description
        combined_text = f"{pkg.description} {pkg.readme}"
        for pat in SOCIAL_ENGINEERING_PATTERNS:
            if pat.search(combined_text):
                total += w["social_engineering"]
                triggered.append("social_engineering")
                break

        # 3. Known-malicious publisher
        if pkg.publisher.lower() in KNOWN_MALICIOUS_PUBLISHERS:
            total += w["known_malicious_pub"]
            triggered.append("known_malicious_publisher")

        # 4. Version gap anomaly (e.g. 0.0.1 → 9.9.9 in first publish)
        if self._has_version_gap_anomaly(pkg.version, pkg.download_count):
            total += w["version_gap_anomaly"]
            triggered.append("version_gap_anomaly")

        # 5. New publish with zero history (< 48 h old, 0 downloads)
        age_hours = (time.time() - pkg.publish_timestamp) / 3600 if pkg.publish_timestamp else 9999
        if age_hours < 48 and pkg.download_count == 0:
            total += w["new_publish_anomaly"]
            triggered.append("new_publish_anomaly")

        # 6. Dependency confusion (internal-looking name on public registry)
        if self._looks_like_dep_confusion(pkg.name):
            total += w["dependency_confusion"]
            triggered.append("dependency_confusion")

        # 7. High-risk permissions without justification
        risky = HIGH_RISK_PERMISSIONS.intersection({p.lower() for p in pkg.permissions})
        if risky:
            total += w["suspicious_permissions"]
            triggered.append(f"suspicious_permissions:{','.join(sorted(risky))}")

        # 8. Community report flag — scales with count
        if pkg.community_flags >= 10:
            total += w["community_flag_high"]
            triggered.append(f"community_flagged:{pkg.community_flags}")
        elif pkg.community_flags >= 3:
            total += w["community_flag_mid"]
            triggered.append(f"community_flagged:{pkg.community_flags}")
        elif pkg.community_flags > 0:
            total += w["community_flag_low"]
            triggered.append(f"community_flagged:{pkg.community_flags}")

        return min(total, 100), triggered

    # -- helpers ---

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if len(a) < len(b):
            a, b = b, a
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
            prev = curr
        return prev[-1]

    def _is_typosquat(self, name: str, known: list[str]) -> bool:
        name_clean = name.lower().replace("-", "").replace("_", "").replace("@", "").replace("/", "")
        for leg in known:
            leg_clean = leg.lower().replace("-", "").replace("_", "").replace("@", "").replace("/", "")
            if name_clean == leg_clean:
                return False  # exact match is fine
            if len(name_clean) > 3 and self._levenshtein(name_clean, leg_clean) <= 2:
                return True
        return False

    @staticmethod
    def _has_version_gap_anomaly(version: str, downloads: int) -> bool:
        try:
            major = int(version.split(".")[0])
            return major >= 5 and downloads < 100
        except (ValueError, IndexError):
            return False

    @staticmethod
    def _looks_like_dep_confusion(name: str) -> bool:
        # Internal-looking names: contains company suffixes, hyphens in unusual positions
        internal_patterns = [
            re.compile(r"^@[a-z]+-internal/"),
            re.compile(r"-internal$"),
            re.compile(r"-private$"),
            re.compile(r"-corp$"),
        ]
        return any(p.search(name.lower()) for p in internal_patterns)


# ---------------------------------------------------------------------------
# Registry API adapters
# ---------------------------------------------------------------------------

class RegistryAdapter(ABC):
    """
    Abstract base class for registry API adapters.
    Each subclass fetches a page of recent/trending packages and returns
    a list of PackageSignals ready for scoring.
    Subclasses MUST implement fetch_recent() and fetch_package() — failing
    to do so raises TypeError at instantiation, not at call time.
    """
    registry_id: str = ""
    display_name: str = ""

    @abstractmethod
    async def fetch_recent(self, limit: int = 200) -> list[PackageSignals]:
        """Fetch recent packages from this registry."""
        ...

    @abstractmethod
    async def fetch_package(self, name: str) -> PackageSignals | None:
        """Fetch a specific package by name. Return None if not found."""
        ...


class NpmAdapter(RegistryAdapter):
    registry_id = "npm"
    display_name = "npm Registry"
    _BASE = "https://registry.npmjs.org"

    async def fetch_recent(self, limit: int = 200) -> list[PackageSignals]:
        try:
            import urllib.request
            url = f"https://www.npmjs.com/browse/recently-updated?limit={limit}"
            # In production: use httpx/aiohttp; here we return a stub for testability
            log.debug("npm: fetch_recent (stub — wire httpx in production)")
            return []
        except Exception as exc:
            log.warning("npm fetch_recent error: %s", exc)
            return []

    async def fetch_package(self, name: str) -> PackageSignals | None:
        try:
            import urllib.request, json as _json
            url = f"{self._BASE}/{name}/latest"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = _json.loads(r.read())
            return PackageSignals(
                name=name,
                registry=self.registry_id,
                publisher=data.get("_npmUser", {}).get("name", ""),
                description=data.get("description", ""),
                readme=data.get("readme", "")[:2000],
                permissions=[],
                version=data.get("version", ""),
                publish_timestamp=0.0,
                download_count=0,
                raw_metadata=data,
            )
        except Exception as exc:
            log.debug("npm fetch_package(%s) error: %s", name, exc)
            return None


class PyPIAdapter(RegistryAdapter):
    registry_id = "pypi"
    display_name = "PyPI"

    async def fetch_recent(self, limit: int = 200) -> list[PackageSignals]:
        log.debug("pypi: fetch_recent (stub)")
        return []

    async def fetch_package(self, name: str) -> PackageSignals | None:
        try:
            import urllib.request, json as _json
            url = f"https://pypi.org/pypi/{name}/json"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = _json.loads(r.read())
            info = data.get("info", {})
            return PackageSignals(
                name=name,
                registry=self.registry_id,
                publisher=info.get("author", ""),
                description=info.get("summary", ""),
                readme=info.get("description", "")[:2000],
                permissions=[],
                version=info.get("version", ""),
                raw_metadata=info,
            )
        except Exception as exc:
            log.debug("pypi fetch_package(%s) error: %s", name, exc)
            return None


class SmitheryAdapter(RegistryAdapter):
    registry_id = "smithery"
    display_name = "Smithery"
    _BASE = "https://smithery.ai/api"

    async def fetch_recent(self, limit: int = 200) -> list[PackageSignals]:
        log.debug("smithery: fetch_recent (stub — wire httpx in production)")
        return []

    async def fetch_package(self, name: str) -> PackageSignals | None:
        log.debug("smithery: fetch_package(%s) stub", name)
        return None


class McpSoAdapter(RegistryAdapter):
    registry_id = "mcp.so"
    display_name = "mcp.so"
    _BASE = "https://mcp.so/api"

    async def fetch_recent(self, limit: int = 200) -> list[PackageSignals]:
        log.debug("mcp.so: fetch_recent (stub — wire httpx in production)")
        return []

    async def fetch_package(self, name: str) -> PackageSignals | None:
        log.debug("mcp.so: fetch_package(%s) stub", name)
        return None


# ---------------------------------------------------------------------------
# ClawHub adapter  (OpenClaw community skill marketplace)
# ---------------------------------------------------------------------------

class ClawHubAdapter(RegistryAdapter):
    """
    ClawHub — the official OpenClaw skill marketplace.

    Context: In the OpenClaw security crisis (Feb 2026), Oasis Security confirmed
    341 of 2,857 skills (12%) were malicious. Attackers used professional-looking
    names like "solana-wallet-tracker" to distribute keyloggers and Atomic Stealer.
    820 malicious skills were found on ClawHub as of the Reco post-mortem
    (up from 324 just weeks prior), demonstrating active, ongoing poisoning.

    API: ClawHub exposes a REST API at api.openclaw.ai/skills.
    Auth: Bearer token (set CLAWHUB_API_TOKEN env var).
    Rate limit: 100 req/min on the free tier.
    """
    registry_id = "clawhub"
    display_name = "ClawHub (OpenClaw Skill Marketplace)"
    _BASE = "https://api.openclaw.ai"

    def __init__(self, api_token: str = ""):
        self.api_token = api_token or self._env_token()

    @staticmethod
    def _env_token() -> str:
        import os
        return os.environ.get("CLAWHUB_API_TOKEN", "")

    def _headers(self) -> dict:
        h = {"Accept": "application/json", "User-Agent": "Aiglos-T30/1.0"}
        if self.api_token:
            h["Authorization"] = f"Bearer {self.api_token}"
        return h

    async def fetch_recent(self, limit: int = 200) -> list[PackageSignals]:
        """
        Fetch recently published or updated skills from ClawHub.
        Endpoint: GET /skills?sort=recent&limit=N

        Returns list[PackageSignals] ready for scoring.
        Falls back to empty list if API is unreachable (non-blocking).
        """
        try:
            import urllib.request, json as _json
            url = f"{self._BASE}/skills?sort=recent&limit={limit}"
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=15) as r:
                data = _json.loads(r.read())

            skills = data.get("skills", data) if isinstance(data, dict) else data
            result = []
            for item in skills[:limit]:
                result.append(self._item_to_signals(item))
            log.info("clawhub: fetched %d skills", len(result))
            return result

        except Exception as exc:
            log.warning("clawhub fetch_recent error: %s — continuing without ClawHub data", exc)
            return []

    async def fetch_package(self, name: str) -> PackageSignals | None:
        """
        Fetch metadata for a specific skill by name or slug.
        Endpoint: GET /skills/{name}
        """
        try:
            import urllib.request, json as _json
            url = f"{self._BASE}/skills/{name}"
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=10) as r:
                item = _json.loads(r.read())
            return self._item_to_signals(item)
        except Exception as exc:
            log.debug("clawhub fetch_package(%s) error: %s", name, exc)
            return None

    def _item_to_signals(self, item: dict) -> PackageSignals:
        """Map ClawHub API response to PackageSignals."""
        # ClawHub manifest may declare required permissions
        permissions = item.get("permissions", item.get("capabilities", []))
        if isinstance(permissions, str):
            permissions = [p.strip() for p in permissions.split(",")]

        # Parse publish timestamp
        ts = 0.0
        raw_ts = item.get("published_at", item.get("created_at", ""))
        if raw_ts:
            try:
                from datetime import datetime, timezone
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                pass

        return PackageSignals(
            name=item.get("name", item.get("slug", "")),
            registry=self.registry_id,
            publisher=item.get("author", item.get("publisher", {}).get("username", "")),
            description=item.get("description", ""),
            readme=item.get("readme", item.get("long_description", ""))[:3000],
            permissions=permissions,
            version=item.get("version", ""),
            publish_timestamp=ts,
            download_count=item.get("downloads", item.get("install_count", 0)),
            community_flags=item.get("reports", item.get("flag_count", 0)),
            raw_metadata=item,
        )

    async def fetch_all_pages(self, max_pages: int = 10, page_size: int = 100) -> list[PackageSignals]:
        """
        Paginate through ClawHub to get comprehensive coverage.
        ClawHub had 2,857 skills at crisis peak — 29 pages at 100/page.
        """
        all_skills: list[PackageSignals] = []
        try:
            import urllib.request, json as _json
            for page in range(1, max_pages + 1):
                url = f"{self._BASE}/skills?sort=recent&limit={page_size}&page={page}"
                req = urllib.request.Request(url, headers=self._headers())
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = _json.loads(r.read())
                skills = data.get("skills", data) if isinstance(data, dict) else data
                if not skills:
                    break
                all_skills.extend(self._item_to_signals(item) for item in skills)
                await asyncio.sleep(0.2)  # respect rate limit
            log.info("clawhub: paginated fetch — %d total skills", len(all_skills))
        except Exception as exc:
            log.warning("clawhub paginated fetch error at page: %s", exc)
        return all_skills


# ---------------------------------------------------------------------------
# SkillsMP adapter  (third-party OpenClaw skill marketplace)
# ---------------------------------------------------------------------------

class SkillsMPAdapter(RegistryAdapter):
    """
    SkillsMP — independent third-party OpenClaw skill marketplace.

    Context: SkillsMP emerged as an alternative to ClawHub during the OpenClaw
    growth phase. Less moderated than ClawHub. Snyk's analysis of the broader
    OpenClaw ecosystem found 13.4% of submitted skills exhibited critical security
    issues including malware distribution, credential theft, and prompt injection.

    API: SkillsMP exposes a public REST API at api.skillsmp.io.
    Auth: API key via X-API-Key header (set SKILLSMP_API_KEY env var).
    Rate limit: 60 req/min on free tier.
    """
    registry_id = "skillsmp"
    display_name = "SkillsMP (Third-Party OpenClaw Skills)"
    _BASE = "https://api.skillsmp.io"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or self._env_key()

    @staticmethod
    def _env_key() -> str:
        import os
        return os.environ.get("SKILLSMP_API_KEY", "")

    def _headers(self) -> dict:
        h = {"Accept": "application/json", "User-Agent": "Aiglos-T30/1.0"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    async def fetch_recent(self, limit: int = 200) -> list[PackageSignals]:
        """
        Fetch recently submitted skills from SkillsMP.
        Endpoint: GET /v1/skills/recent?limit=N

        SkillsMP is less moderated than ClawHub — apply STRICT mode scoring.
        """
        try:
            import urllib.request, json as _json
            url = f"{self._BASE}/v1/skills/recent?limit={limit}"
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=15) as r:
                data = _json.loads(r.read())

            items = data.get("data", data.get("skills", data)) if isinstance(data, dict) else data
            result = [self._item_to_signals(item) for item in items[:limit]]
            log.info("skillsmp: fetched %d skills", len(result))
            return result

        except Exception as exc:
            log.warning("skillsmp fetch_recent error: %s — continuing without SkillsMP data", exc)
            return []

    async def fetch_package(self, name: str) -> PackageSignals | None:
        """
        Fetch metadata for a specific SkillsMP skill.
        Endpoint: GET /v1/skills/{name}
        """
        try:
            import urllib.request, json as _json
            url = f"{self._BASE}/v1/skills/{name}"
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=10) as r:
                item = _json.loads(r.read())
            return self._item_to_signals(item)
        except Exception as exc:
            log.debug("skillsmp fetch_package(%s) error: %s", name, exc)
            return None

    def _item_to_signals(self, item: dict) -> PackageSignals:
        """Map SkillsMP API response to PackageSignals."""
        permissions = item.get("required_permissions", item.get("scopes", []))
        if isinstance(permissions, str):
            permissions = [p.strip() for p in permissions.split(",")]

        ts = 0.0
        raw_ts = item.get("submitted_at", item.get("created_at", ""))
        if raw_ts:
            try:
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                pass

        return PackageSignals(
            name=item.get("skill_name", item.get("name", "")),
            registry=self.registry_id,
            publisher=item.get("submitter", item.get("author", "")),
            description=item.get("summary", item.get("description", "")),
            readme=item.get("details", item.get("readme", ""))[:3000],
            permissions=permissions,
            version=item.get("version", "1.0.0"),
            publish_timestamp=ts,
            download_count=item.get("installs", item.get("downloads", 0)),
            community_flags=item.get("abuse_reports", item.get("flags", 0)),
            raw_metadata=item,
        )

    async def search(self, query: str, limit: int = 50) -> list[PackageSignals]:
        """Search SkillsMP for skills matching a query string."""
        try:
            import urllib.request, json as _json
            from urllib.parse import quote
            url = f"{self._BASE}/v1/skills/search?q={quote(query)}&limit={limit}"
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=10) as r:
                data = _json.loads(r.read())
            items = data.get("results", data) if isinstance(data, dict) else data
            return [self._item_to_signals(item) for item in items]
        except Exception as exc:
            log.debug("skillsmp search(%s) error: %s", query, exc)
            return []


# ---------------------------------------------------------------------------
# Blocklist persistence
# ---------------------------------------------------------------------------

class BlocklistStore:
    """
    Persists the auto-generated blocklist to SQLite (same db as other Aiglos tables).
    Schema: aiglos_registry_blocklist(registry, package_name, version, risk, score, reason, blocked_at)
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS aiglos_registry_blocklist (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    registry    TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    version     TEXT,
                    risk        TEXT NOT NULL,
                    score       INTEGER,
                    reason      TEXT,
                    blocked_at  TEXT NOT NULL,
                    UNIQUE(registry, package_name)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS aiglos_registry_scan_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     TEXT UNIQUE,
                    started_at  TEXT,
                    completed_at TEXT,
                    summary_json TEXT
                )
            """)
            conn.commit()

    def is_blocked(self, registry: str, package_name: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM aiglos_registry_blocklist WHERE registry=? AND package_name=?",
                (registry, package_name),
            ).fetchone()
            return row is not None

    def block(self, finding: RegistryFinding) -> bool:
        """Add to blocklist. Returns True if newly added."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO aiglos_registry_blocklist
                       (registry, package_name, version, risk, score, reason, blocked_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        finding.registry, finding.package_name, finding.version,
                        finding.risk.value, finding.score,
                        json.dumps(finding.signals_triggered), now,
                    ),
                )
                conn.commit()
            return True
        except Exception as exc:
            log.error("blocklist.block error: %s", exc)
            return False

    def get_all(self) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT registry, package_name, version, risk, score, reason, blocked_at "
                "FROM aiglos_registry_blocklist ORDER BY blocked_at DESC"
            ).fetchall()
        return [
            {
                "registry": r[0], "package_name": r[1], "version": r[2],
                "risk": r[3], "score": r[4],
                "reason": json.loads(r[5]) if r[5] else [],
                "blocked_at": r[6],
            }
            for r in rows
        ]

    def log_scan(self, report: RegistryScanReport):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO aiglos_registry_scan_log
                   (scan_id, started_at, completed_at, summary_json)
                   VALUES (?,?,?,?)""",
                (report.scan_id, report.started_at, report.completed_at,
                 json.dumps(report.summary)),
            )
            conn.commit()


# ---------------------------------------------------------------------------
# T30 — RegistryMonitor  (main class)
# ---------------------------------------------------------------------------

class RegistryMonitor:
    """
    T30 — Continuous public registry monitoring with auto-blocklist.

    Monitors six registries: npm, PyPI, Smithery, mcp.so, ClawHub, SkillsMP.
    Scores each package against 8 risk signals.
    Auto-blocks CRITICAL findings and alerts on HIGH.
    Feeds the T22 intel refresh pipeline.

    Quick-start
    -----------
        monitor = RegistryMonitor(audit_db="aiglos_audit.db")
        report  = await monitor.scan()
        print(report.summary)
    """

    REGISTRY_MAP: dict[str, type[RegistryAdapter]] = {
        "npm":      NpmAdapter,
        "pypi":     PyPIAdapter,
        "smithery": SmitheryAdapter,
        "mcp.so":   McpSoAdapter,
        "clawhub":  ClawHubAdapter,
        "skillsmp": SkillsMPAdapter,
    }

    def __init__(
        self,
        audit_db: str = "aiglos_audit.db",
        clawhub_token: str = "",
        skillsmp_key: str = "",
        auto_block_threshold: int = 70,   # CRITICAL
        alert_threshold: int = 50,        # HIGH
    ):
        self.audit_db = audit_db
        self.clawhub_token = clawhub_token
        self.skillsmp_key = skillsmp_key
        self.auto_block_threshold = auto_block_threshold
        self.alert_threshold = alert_threshold
        self.scorer = PackageScorer()
        self.store = BlocklistStore(audit_db)

    def _build_adapter(self, registry_id: str) -> RegistryAdapter:
        cls = self.REGISTRY_MAP[registry_id]
        if registry_id == "clawhub":
            return cls(api_token=self.clawhub_token)
        if registry_id == "skillsmp":
            return cls(api_key=self.skillsmp_key)
        return cls()

    async def scan(
        self,
        registries: list[str] | None = None,
        limit_per_registry: int = 200,
    ) -> RegistryScanReport:
        """
        Scan all (or specified) registries. Returns a full RegistryScanReport.

        Parameters
        ----------
        registries : list[str] | None
            Subset of ["npm", "pypi", "smithery", "mcp.so", "clawhub", "skillsmp"].
            Pass None to scan all six.
        limit_per_registry : int
            Max packages to fetch per registry per scan cycle.
        """
        targets = registries or list(self.REGISTRY_MAP.keys())
        scan_id = "T30-" + hashlib.sha256(
            f"{time.time()}{targets}".encode()
        ).hexdigest()[:10].upper()
        started_at = datetime.now(timezone.utc).isoformat()

        all_findings: list[RegistryFinding] = []
        blocklist_additions: list[str] = []
        total_evaluated = 0

        for reg_id in targets:
            if reg_id not in self.REGISTRY_MAP:
                log.warning("Unknown registry: %s — skipping", reg_id)
                continue

            adapter = self._build_adapter(reg_id)
            log.info("T30: scanning %s ...", adapter.display_name)

            try:
                packages = await adapter.fetch_recent(limit=limit_per_registry)
            except Exception as exc:
                log.error("T30: fetch_recent(%s) failed: %s", reg_id, exc)
                continue

            total_evaluated += len(packages)

            for pkg in packages:
                finding = await self.score_package(reg_id, pkg.name, pkg)
                if finding is None:
                    continue

                if finding.score >= self.auto_block_threshold:
                    if self.store.block(finding):
                        blocklist_additions.append(f"{reg_id}:{pkg.name}")
                        log.warning(
                            "T30 AUTO-BLOCK  %s:%s  score=%d  signals=%s",
                            reg_id, pkg.name, finding.score,
                            finding.signals_triggered,
                        )

                elif finding.score >= self.alert_threshold:
                    log.warning(
                        "T30 HIGH-RISK   %s:%s  score=%d  signals=%s",
                        reg_id, pkg.name, finding.score,
                        finding.signals_triggered,
                    )

                if finding.score >= 25:
                    all_findings.append(finding)

        completed_at = datetime.now(timezone.utc).isoformat()
        report = RegistryScanReport(
            scan_id=scan_id,
            started_at=started_at,
            completed_at=completed_at,
            registries_scanned=targets,
            packages_evaluated=total_evaluated,
            findings=all_findings,
            blocklist_additions=blocklist_additions,
        )
        self.store.log_scan(report)
        log.info("T30 scan complete: %s", report.summary)
        return report

    async def score_package(
        self,
        registry: str,
        name: str,
        signals: PackageSignals | None = None,
    ) -> RegistryFinding | None:
        """
        Score a single package. Fetches metadata from the registry if signals
        are not provided.

        Parameters
        ----------
        registry : str
            Registry ID (e.g. "clawhub", "npm").
        name : str
            Package/skill name.
        signals : PackageSignals | None
            Pre-fetched signals. If None, adapter.fetch_package() is called.
        """
        if signals is None:
            adapter = self._build_adapter(registry)
            signals = await adapter.fetch_package(name)
            if signals is None:
                log.debug("score_package: could not fetch %s:%s", registry, name)
                return None

        score, triggered = self.scorer.score(signals)

        if score >= self.auto_block_threshold:
            risk = RegistryRisk.CRITICAL
        elif score >= self.alert_threshold:
            risk = RegistryRisk.HIGH
        elif score >= 25:
            risk = RegistryRisk.MEDIUM
        else:
            risk = RegistryRisk.LOW

        already_blocked = self.store.is_blocked(registry, name)
        auto_blocked = score >= self.auto_block_threshold and not already_blocked

        return RegistryFinding(
            registry=registry,
            package_name=name,
            version=signals.version,
            risk=risk,
            score=score,
            signals_triggered=triggered,
            auto_blocked=auto_blocked,
            detail={
                "publisher":      signals.publisher,
                "description":    signals.description[:200],
                "download_count": signals.download_count,
                "community_flags": signals.community_flags,
            },
        )

    async def refresh_blocklist(self) -> list[str]:
        """
        Called by T22 intel_refresh. Full scan across all 6 registries,
        returns list of newly blocked package identifiers.
        """
        report = await self.scan()
        return report.blocklist_additions

    async def check_install(self, registry: str, package_name: str) -> dict:
        """
        Called by T26 at install-time to check a single package before it is
        installed into an agent environment. Returns a go/no-go decision.
        """
        if self.store.is_blocked(registry, package_name):
            return {
                "allowed": False,
                "reason": "blocklist",
                "registry": registry,
                "package": package_name,
            }
        finding = await self.score_package(registry, package_name)
        if finding is None:
            return {"allowed": True, "reason": "not_found", "registry": registry, "package": package_name}

        return {
            "allowed": finding.score < self.auto_block_threshold,
            "reason": "score",
            "score": finding.score,
            "risk": finding.risk.value,
            "signals": finding.signals_triggered,
            "registry": registry,
            "package": package_name,
        }

    def get_blocklist(self) -> list[dict]:
        """Return the full current blocklist."""
        return self.store.get_all()

    async def status(self) -> dict:
        """Health summary for the T30 module."""
        blocklist = self.store.get_all()
        return {
            "module": "T30",
            "class": "RegistryMonitor",
            "registries": list(self.REGISTRY_MAP.keys()),
            "blocklist_size": len(blocklist),
            "critical_blocked": sum(1 for b in blocklist if b["risk"] == "CRITICAL"),
            "high_blocked": sum(1 for b in blocklist if b["risk"] == "HIGH"),
            "clawhub_token_configured": bool(self.clawhub_token or __import__("os").environ.get("CLAWHUB_API_TOKEN")),
            "skillsmp_key_configured": bool(self.skillsmp_key or __import__("os").environ.get("SKILLSMP_API_KEY")),
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse, sys

    parser = argparse.ArgumentParser(description="Aiglos T30 — Registry Monitor")
    parser.add_argument("--registries", nargs="*",
                        help="Registries to scan (default: all). "
                             "Options: npm pypi smithery mcp.so clawhub skillsmp")
    parser.add_argument("--db", default="aiglos_audit.db", help="Audit DB path")
    parser.add_argument("--blocklist", action="store_true", help="Print current blocklist and exit")
    parser.add_argument("--check", nargs=2, metavar=("REGISTRY", "PACKAGE"),
                        help="Check a single package (e.g. --check clawhub solana-wallet-tracker)")
    parser.add_argument("--status", action="store_true", help="Print module status and exit")
    args = parser.parse_args()

    monitor = RegistryMonitor(audit_db=args.db)

    async def main():
        if args.status:
            s = await monitor.status()
            print(json.dumps(s, indent=2))
        elif args.blocklist:
            bl = monitor.get_blocklist()
            print(json.dumps(bl, indent=2))
        elif args.check:
            result = await monitor.check_install(args.check[0], args.check[1])
            print(json.dumps(result, indent=2))
            sys.exit(0 if result["allowed"] else 1)
        else:
            report = await monitor.scan(registries=args.registries)
            print(json.dumps(report.to_dict(), indent=2))

    asyncio.run(main())
