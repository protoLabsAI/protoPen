"""Data models for the protoPen security knowledge base."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CVE:
    id: str  # CVE ID (e.g., "CVE-2024-12345")
    title: str = ""
    description: str = ""
    severity: str = ""  # critical/high/medium/low
    cvss_score: float = 0.0
    cvss_vector: str = ""
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_maturity: str = "none"  # poc/weaponized/active/none
    tags: list[str] = field(default_factory=list)
    published_at: str = ""
    discovered_at: str = ""
    analyzed_at: str = ""
    notes: str = ""


@dataclass
class Exploit:
    id: int = 0
    cve_id: str = ""
    title: str = ""
    description: str = ""
    source: str = ""  # exploit-db/github/custom
    source_url: str = ""
    platform: str = ""  # linux/windows/multi/hardware
    exploit_type: str = ""  # remote/local/webapps/dos/shellcode
    verified: bool = False
    code_path: str = ""
    discovered_at: str = ""
    tested_at: str = ""
    notes: str = ""


@dataclass
class Advisory:
    id: int = 0
    source: str = ""  # vendor/CERT/researcher
    title: str = ""
    content: str = ""
    severity: str = ""
    affected_products: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    url: str = ""
    published_at: str = ""
    discovered_at: str = ""
    notes: str = ""


@dataclass
class ThreatIntel:
    id: int = 0
    content: str = ""
    source: str = ""
    source_type: str = ""  # cve/advisory/exploit/engagement/osint
    topic: str = ""
    intel_type: str = ""  # indicator/technique/correlation/recommendation
    severity: str = ""
    target_relevance: str = ""  # JSON: which targets this affects
    created_at: str = ""


@dataclass
class Topic:
    id: int = 0
    name: str = ""
    description: str = ""
    keywords: list[str] = field(default_factory=list)
    priority: int = 2
    active: bool = True
    created_at: str = ""
    last_scanned_at: str = ""


@dataclass
class Digest:
    id: int = 0
    title: str = ""
    content: str = ""
    digest_type: str = ""  # daily/weekly/threat_brief/engagement_summary
    topic: str = ""
    cves_referenced: list[str] = field(default_factory=list)
    created_at: str = ""
