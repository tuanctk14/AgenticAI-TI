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
    """CISA Known Exploited Vulnerabilities (with VulnCheck fallback)"""
    listed: bool = False
    date_added: Optional[str] = None  # YYYY-MM-DD
    due_date: Optional[str] = None
    known_ransomware_campaign_use: bool = False
    source: str = "cisa"  # "cisa" or "vulncheck"


class VulnCheckData(BaseModel):
    """Exploit intelligence from VulnCheck"""
    public_exploit_available: bool = False
    metasploit_available: bool = False
    exploit_maturity: Optional[str] = None  # "active", "functional", "poc", "unproven"
    ransomware_activity: bool = False
    threat_actor_references: List[str] = Field(default_factory=list)
    botnet_activity: bool = False
    exploitation_observed: bool = False


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
    vulncheck: Optional[VulnCheckData] = None

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
