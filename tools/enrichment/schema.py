"""
tools/enrichment/schema.py - Unified CVE data schema with source tracking

Single source of truth for enriched CVE data across all providers.
Supports fallback chains: NVD → VulnCheck, CISA → VulnCheck, etc.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class DataSource(BaseModel):
    """Track where a piece of data came from"""
    value: Any
    source: str  # "nvd", "vulncheck", "cisa", "first", etc.
    confidence: float = 1.0  # 0.0-1.0
    fetched_at: Optional[datetime] = None


class CVEMetadata(BaseModel):
    """Core CVE metadata (NVD canonical + VulnCheck fallback)"""
    cve_id: str
    description: str
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class CVSSData(BaseModel):
    """CVSS score with fallback support"""
    score: DataSource  # value: float, source: "nvd"|"vulncheck"
    severity: str  # "CRITICAL", "HIGH", etc.
    vector: Optional[str] = None


class CWEData(BaseModel):
    """CWE IDs with fallback support"""
    ids: DataSource  # value: List[str], source: "nvd"|"vulncheck"


class CPEData(BaseModel):
    """CPE entries with fallback support"""
    entries: DataSource  # value: List[str], source: "nvd"|"vulncheck"


class EPSSData(BaseModel):
    """Exploitation Probability Scoring System (FIRST API)"""
    score: Optional[float] = None  # 0.0-1.0
    percentile: Optional[float] = None  # 0-100
    available: bool = False


class KEVData(BaseModel):
    """CISA Known Exploited Vulnerabilities. Always from CISA, not Vulners."""
    listed: bool = False
    date_added: Optional[str] = None  # YYYY-MM-DD
    due_date: Optional[str] = None
    known_ransomware_campaign_use: bool = False
    source: str = "cisa"  # Always CISA official feed


class VulnersData(BaseModel):
    """Exploit intelligence from Vulners API. Always from Vulners, not other sources."""
    public_exploit_available: bool = False
    metasploit_available: bool = False
    exploit_count: int = 0
    exploit_sources: List[str] = Field(default_factory=list)  # e.g., ["exploit-db", "github", "metasploit"]
    exploit_references: List[str] = Field(default_factory=list)  # URLs to exploits


class DataQuality(BaseModel):
    """Metadata about data sources and quality"""
    cvss_source: str  # "nvd" or "vulncheck"
    cwe_source: str  # "nvd" or "vulncheck"
    cpe_source: str  # "nvd" or "vulncheck"
    kev_source: Optional[str] = None  # "cisa" or "vulncheck"
    epss_available: bool = False
    missing_fields: List[str] = Field(default_factory=list)


class UnifiedCVE(BaseModel):
    """
    Complete enriched CVE object - single source of truth.

    Tracks all data with source attribution.
    Supports fallback chains automatically.

    PHASE 1 EXTENSION (G1-G2):
    - capec_ids: CAPEC attack patterns from CWE
    - attack_techniques: ATT&CK techniques from CAPEC chain
    """
    cve_id: str

    # Core metadata
    metadata: CVEMetadata

    # Scoring (with source tracking, Optional during partial enrichment)
    cvss: Optional[CVSSData] = None
    cwe: Optional[CWEData] = None
    cpe: Optional[CPEData] = None

    # Enrichment data
    epss: Optional[EPSSData] = None
    kev: Optional[KEVData] = None
    vulncheck: Optional[VulnersData] = None  # Now contains Vulners exploit intelligence

    # PHASE 1: Attack chain (G1-G2)
    capec_ids: Optional[List[Dict]] = None  # [{"id": "126", "name": "...", "likelihood": "High", "abstraction": "Standard"}]
    attack_techniques: Optional[List[Dict]] = None  # [{"t_number": "T1083", "name": "...", "tactics": [...], "capec_id": "3", ...}]

    # PHASE 3: Ranked attack paths + controls (G8-G10)
    cve_priority_score: Optional[float] = None  # 0-1 (Layer 1)
    cve_priority_tier: Optional[str] = None  # "CRITICAL" | "STANDARD" | "LOW"
    attack_paths: Optional[List[Dict]] = None  # [{"rank": 1, "relevance_score": 0.88, "cwe": "...", "capec": {...}, "attack_technique": {...}}]
    recommended_controls: Optional[List[Dict]] = None  # [{"rank": 1, "control": "SI-10", "weight": 1.69, "techniques": [...]}]
    attack_paths_filtered_count: int = 0  # How many paths were filtered (noise)

    # Computed risk
    unified_risk_score: float = 0.0
    enrichment_summary: str = ""

    # Data quality tracking
    data_quality: Optional[DataQuality] = None

    # Enrichment timestamps
    enriched_at: datetime = Field(default_factory=datetime.utcnow)
    cache_hit: bool = False

    class Config:
        """Pydantic config"""
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

    def to_dict(self, include_internals: bool = False) -> dict:
        """Convert to dict for JSON serialization"""
        data = self.model_dump()
        return data

    def has_all_core_data(self) -> bool:
        """Check if CVE has required CVSS/CWE/CPE data"""
        return (
            self.cvss is not None and self.cvss.score.value is not None
            and self.cwe is not None and self.cwe.ids.value
            and self.cpe is not None and self.cpe.entries.value
        )

    def get_data_completeness(self) -> float:
        """Return data completeness percentage (0-100)"""
        checks = [
            self.cvss is not None and self.cvss.score.value is not None,
            self.cwe is not None and self.cwe.ids.value,
            self.cpe is not None and self.cpe.entries.value,
            self.epss is not None and self.epss.score is not None,
            self.kev is not None and self.kev.listed,
            self.vulncheck is not None,
        ]
        return (sum(checks) / len(checks)) * 100
