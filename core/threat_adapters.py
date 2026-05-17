"""
core/threat_adapters.py - Source Adapters for Normalization

Each intelligence source has its own adapter.
Adapters normalize raw tool outputs → canonical threat schema objects.

This layer ensures:
- Canonical schema is source-agnostic
- Raw API responses never leak to agents
- Consistent data quality across sources
- Easy to add new sources without changing agents
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    RiskContext,
    SeverityLevel,
    IOCType,
    Relationship,
    RelationshipType,
    EntityType,
)


# ============================================================
# ADAPTER INTERFACE
# ============================================================

class ThreatSourceAdapter(ABC):
    """Base interface for all threat source adapters."""

    @abstractmethod
    def normalize_vulnerability(self, raw_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Normalize raw CVE data to canonical Vulnerability entity."""
        pass

    @abstractmethod
    def normalize_ioc(self, raw_data: Dict[str, Any]) -> Optional[IOC]:
        """Normalize raw IOC data to canonical IOC entity."""
        pass

    @abstractmethod
    def normalize_asset(self, raw_data: Dict[str, Any]) -> Optional[Asset]:
        """Normalize raw asset data to canonical Asset entity."""
        pass


# ============================================================
# NVD ADAPTER
# ============================================================

class NVDAdapter(ThreatSourceAdapter):
    """
    Adapter for NVD API responses.
    Normalizes: CVE data, CWE, CPE, descriptions.
    """

    def normalize_vulnerability(self, raw_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """
        Convert NVD CVE response to Vulnerability entity.

        Expected raw_data structure:
        {
            "id": "CVE-2026-8181",
            "description": "...",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/...",
            "cwe_ids": ["CWE-79"],
            "cpe_uris": ["cpe:2.3:a:..."],
            "references": ["https://..."],
            "published": "2026-05-16",
            "modified": "2026-05-17"
        }
        """
        try:
            cve_id = raw_data.get("id", "").upper()
            if not cve_id.startswith("CVE-"):
                return None

            # Convert CVSS severity string to enum
            severity_str = raw_data.get("severity", "UNKNOWN").upper()
            try:
                severity = SeverityLevel[severity_str]
            except KeyError:
                severity = SeverityLevel.UNKNOWN

            # Build risk context from NVD data
            risk_context = RiskContext(
                cvss_score=raw_data.get("cvss_score"),
                cvss_vector=raw_data.get("cvss_vector"),
                cvss_source="nvd",
                data_sources=["nvd"],
            )

            vuln = Vulnerability(
                id=cve_id,
                description=raw_data.get("description", ""),
                cwe_ids=raw_data.get("cwe_ids", []),
                cpe_uris=raw_data.get("cpe_uris", []),
                references=raw_data.get("references", []),
                severity=severity,
                risk_context=risk_context,
                published_date=raw_data.get("published"),
                modified_date=raw_data.get("modified"),
                ttl_hours=24,
            )
            return vuln
        except Exception as e:
            print(f"[NVD Adapter] Error normalizing CVE: {e}")
            return None

    def normalize_ioc(self, raw_data: Dict[str, Any]) -> Optional[IOC]:
        """NVD doesn't provide IOC data."""
        return None

    def normalize_asset(self, raw_data: Dict[str, Any]) -> Optional[Asset]:
        """NVD doesn't provide asset data."""
        return None


# ============================================================
# EPSS ADAPTER
# ============================================================

class EPSSAdapter(ThreatSourceAdapter):
    """
    Adapter for EPSS API responses.
    Enriches vulnerability risk context.
    """

    def normalize_vulnerability(self, raw_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """
        EPSS adapter doesn't create vulnerabilities, only enriches.
        Use merge_epss_enrichment() instead.
        """
        return None

    def merge_epss_enrichment(
        self,
        vulnerability: Vulnerability,
        epss_data: Dict[str, Any]
    ) -> Vulnerability:
        """
        Merge EPSS data into existing vulnerability.

        Expected epss_data:
        {
            "cve": "CVE-2026-8181",
            "epss": 0.97,
            "percentile": 98.5,
            "date": "2026-05-17"
        }
        """
        if vulnerability.risk_context is None:
            vulnerability.risk_context = RiskContext()

        vulnerability.risk_context.epss_score = epss_data.get("epss")
        vulnerability.risk_context.epss_percentile = epss_data.get("percentile")

        if "epss" not in vulnerability.risk_context.data_sources:
            vulnerability.risk_context.data_sources.append("epss")

        return vulnerability

    def normalize_ioc(self, raw_data: Dict[str, Any]) -> Optional[IOC]:
        return None

    def normalize_asset(self, raw_data: Dict[str, Any]) -> Optional[Asset]:
        return None


# ============================================================
# KEV ADAPTER
# ============================================================

class KEVAdapter(ThreatSourceAdapter):
    """
    Adapter for CISA Known Exploited Vulnerabilities.
    Marks CVEs as exploited in wild.
    """

    def normalize_vulnerability(self, raw_data: Dict[str, Any]) -> Optional[Vulnerability]:
        return None

    def merge_kev_enrichment(
        self,
        vulnerability: Vulnerability,
        kev_data: Dict[str, Any]
    ) -> Vulnerability:
        """
        Merge KEV data into existing vulnerability.

        Expected kev_data:
        {
            "cveID": "CVE-2026-8181",
            "dateAdded": "2026-05-17",
            ...
        }
        """
        if vulnerability.risk_context is None:
            vulnerability.risk_context = RiskContext()

        vulnerability.risk_context.kev_listed = kev_data.get("dateAdded") is not None
        vulnerability.risk_context.kev_added_date = kev_data.get("dateAdded")

        if "kev" not in vulnerability.risk_context.data_sources:
            vulnerability.risk_context.data_sources.append("kev")

        return vulnerability

    def normalize_ioc(self, raw_data: Dict[str, Any]) -> Optional[IOC]:
        return None

    def normalize_asset(self, raw_data: Dict[str, Any]) -> Optional[Asset]:
        return None


# ============================================================
# VULNERS ADAPTER
# ============================================================

class VulnersAdapter(ThreatSourceAdapter):
    """
    Adapter for Vulners API.
    Provides: exploit availability, exploit timeline, fallback CVSS/EPSS/CWE.
    """

    def normalize_vulnerability(self, raw_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """
        Vulners can provide fallback vulnerability data.
        Use for CVEs not in NVD (rare edge case).
        """
        try:
            cve_id = raw_data.get("id", "").upper()
            if not cve_id.startswith("CVE-"):
                return None

            risk_context = RiskContext(
                cvss_score=raw_data.get("cvss", {}).get("score"),
                epss_score=raw_data.get("epss"),
                public_exploit_available=raw_data.get("public_exploit_available", False),
                metasploit_available=raw_data.get("metasploit_available", False),
                exploit_count=raw_data.get("exploit_count", 0),
                data_sources=["vulners"],
            )

            vuln = Vulnerability(
                id=cve_id,
                description=raw_data.get("description", ""),
                cwe_ids=raw_data.get("cwe_ids", []),
                risk_context=risk_context,
                ttl_hours=12,
            )
            return vuln
        except Exception as e:
            print(f"[Vulners Adapter] Error normalizing vulnerability: {e}")
            return None

    def merge_vulners_enrichment(
        self,
        vulnerability: Vulnerability,
        vulners_data: Dict[str, Any]
    ) -> Vulnerability:
        """Merge Vulners exploit intelligence into vulnerability."""
        if vulnerability.risk_context is None:
            vulnerability.risk_context = RiskContext()

        # Exploit intelligence
        vulnerability.risk_context.public_exploit_available = vulners_data.get(
            "public_exploit_available", False
        )
        vulnerability.risk_context.metasploit_available = vulners_data.get(
            "metasploit_available", False
        )
        vulnerability.risk_context.exploit_count = vulners_data.get("exploit_count", 0)
        vulnerability.risk_context.exploit_sources = vulners_data.get(
            "exploit_sources", []
        )

        # Fallback EPSS if NVD missing
        if not vulnerability.risk_context.epss_score:
            vulnerability.risk_context.epss_score = vulners_data.get("epss")

        # Fallback CWE if NVD missing
        if not vulnerability.cwe_ids:
            vulnerability.cwe_ids = vulners_data.get("cwe_ids", [])

        if "vulners" not in vulnerability.risk_context.data_sources:
            vulnerability.risk_context.data_sources.append("vulners")

        return vulnerability

    def normalize_ioc(self, raw_data: Dict[str, Any]) -> Optional[IOC]:
        return None

    def normalize_asset(self, raw_data: Dict[str, Any]) -> Optional[Asset]:
        return None


# ============================================================
# OPENCTI ADAPTER
# ============================================================

class OpenCTIAdapter(ThreatSourceAdapter):
    """
    Adapter for OpenCTI API responses.
    Provides: IOC, Malware, Campaign, Threat Actor relationships.
    """

    def normalize_ioc(self, raw_data: Dict[str, Any]) -> Optional[IOC]:
        """
        Normalize OpenCTI indicator/observable to IOC entity.

        Expected raw_data:
        {
            "id": "192.168.1.100",
            "type": "ipv4-addr",
            "value": "192.168.1.100",
            "created": "2026-05-16",
            ...
        }
        """
        try:
            value = raw_data.get("value", "").strip()
            if not value:
                return None

            # Map OpenCTI types to IOCType
            opencti_type = raw_data.get("type", "").lower()
            ioc_type = self._map_opencti_type_to_ioc(opencti_type)
            if not ioc_type:
                return None

            # Normalize ID (make it consistent)
            ioc_id = value.lower()

            ioc = IOC(
                id=ioc_id,
                ioc_type=ioc_type,
                value=value,
                description=raw_data.get("description"),
                first_seen=raw_data.get("created"),
                last_seen=raw_data.get("modified"),
                observation_count=raw_data.get("observation_count", 1),
                ttl_hours=6,
            )
            return ioc
        except Exception as e:
            print(f"[OpenCTI Adapter] Error normalizing IOC: {e}")
            return None

    def normalize_vulnerability(self, raw_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """OpenCTI may provide CVE references."""
        return None

    def normalize_asset(self, raw_data: Dict[str, Any]) -> Optional[Asset]:
        """OpenCTI doesn't provide internal asset data."""
        return None

    def normalize_relationship(
        self,
        raw_data: Dict[str, Any]
    ) -> Optional[Relationship]:
        """
        Normalize OpenCTI relationship object.

        Expected raw_data:
        {
            "source_id": "malware-id",
            "target_id": "ioc-id",
            "relationship_type": "uses"
        }
        """
        try:
            source_id = raw_data.get("source_id")
            target_id = raw_data.get("target_id")
            rel_type = raw_data.get("relationship_type", "").lower()

            if not source_id or not target_id or not rel_type:
                return None

            # Map to canonical relationship type
            canonical_rel = self._map_relationship_type(rel_type)
            if not canonical_rel:
                return None

            relationship = Relationship(
                source_id=source_id,
                source_type=raw_data.get("source_type", EntityType.MALWARE),
                target_id=target_id,
                target_type=raw_data.get("target_type", EntityType.IOC),
                relationship_type=canonical_rel,
                confidence=raw_data.get("confidence", 0.7),
                evidence_sources=["opencti"],
            )
            return relationship
        except Exception as e:
            print(f"[OpenCTI Adapter] Error normalizing relationship: {e}")
            return None

    @staticmethod
    def _map_opencti_type_to_ioc(opencti_type: str) -> Optional[IOCType]:
        """Map OpenCTI observable types to canonical IOCType."""
        mapping = {
            "ipv4-addr": IOCType.IP,
            "ipv6-addr": IOCType.IP,
            "domain-name": IOCType.DOMAIN,
            "url": IOCType.URL,
            "file": IOCType.HASH,
            "x-misp-email-src": IOCType.EMAIL,
        }
        return mapping.get(opencti_type)

    @staticmethod
    def _map_relationship_type(opencti_rel: str) -> Optional[RelationshipType]:
        """Map OpenCTI relationship types to canonical RelationshipType."""
        mapping = {
            "uses": RelationshipType.USES,
            "linked-to": RelationshipType.LINKED_TO,
            "exploits": RelationshipType.EXPLOITS,
            "communicates-with": RelationshipType.COMMUNICATES_WITH,
            "observed-in": RelationshipType.OBSERVED_IN,
        }
        return mapping.get(opencti_rel)


# ============================================================
# INTERNAL TELEMETRY ADAPTER
# ============================================================

class InternalTelemetryAdapter(ThreatSourceAdapter):
    """
    Adapter for internal asset/exposure data (CMDB, scanners, etc).
    Provides: Asset information, CVE mappings, exposure context.
    """

    def normalize_asset(self, raw_data: Dict[str, Any]) -> Optional[Asset]:
        """
        Normalize internal asset data to canonical Asset entity.

        Expected raw_data:
        {
            "device_id": "dmz-web-01",
            "hostname": "dmz-web-01",
            "ip": "10.0.1.5",
            "os": "Ubuntu 20.04",
            "internet_facing": true,
            "criticality": "high",
            "software": [...],
            "vulnerable_cves": ["CVE-2026-8181"]
        }
        """
        try:
            device_id = raw_data.get("device_id") or raw_data.get("hostname")
            if not device_id:
                return None

            asset = Asset(
                id=device_id,
                hostname=raw_data.get("hostname", device_id),
                ip_address=raw_data.get("ip"),
                os=raw_data.get("os"),
                location=raw_data.get("location", "Internal"),
                criticality=raw_data.get("criticality"),
                internet_facing=raw_data.get("internet_facing", False),
                exposed_ports=raw_data.get("exposed_ports", []),
                vulnerable_cves=raw_data.get("vulnerable_cves", []),
                cpe_mappings=raw_data.get("cpe_mappings", []),
                ttl_hours=48,
            )
            return asset
        except Exception as e:
            print(f"[Internal Adapter] Error normalizing asset: {e}")
            return None

    def normalize_vulnerability(self, raw_data: Dict[str, Any]) -> Optional[Vulnerability]:
        return None

    def normalize_ioc(self, raw_data: Dict[str, Any]) -> Optional[IOC]:
        return None
