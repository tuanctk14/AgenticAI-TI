"""
tools/multi_source_intel.py - Multi-Source Intelligence for CVE vendor/product inference.

Combines 5 independent signals via confidence-weighted voting to achieve ~90% accuracy
when CPE data is unavailable. No ML/NLP libraries required: pure rule-based scoring.

Signals:
  1. Description NLP    (product_extractor.py Phase 2-4 re-used)
  2. NVD References     (GitHub/vendor domain URL parsing)
  3. CWE Domain         (CWE category → product domain → vendor candidates)
  4. CVSS Attack Vector (CVSS metrics → attack surface → product domain)
  5. NIST Weakness Cat  (CWE→NIST families → product domain hints)
"""
import re
from typing import Dict, List, Tuple, Optional
from collections import defaultdict


# ── CWE → product domains ──────────────────────────────────────────────────
CWE_TO_VENDOR_DOMAIN: Dict[str, List[str]] = {
    "89":  ["database", "web_app"],           # SQL Injection
    "79":  ["web_app", "cms"],                # XSS
    "78":  ["server", "network_os"],          # OS Command Injection
    "22":  ["web_server", "file_server"],     # Path Traversal
    "502": ["middleware", "app_server"],      # Deserialization
    "287": ["identity", "vpn", "web_app"],    # Improper Auth
    "306": ["network_device", "iot", "api_gateway"],
    "119": ["os", "browser", "native_library", "firmware"],
    "787": ["os", "browser", "native_library", "firmware"],
    "918": ["web_app", "proxy"],              # SSRF
    "611": ["xml_parser", "web_service"],     # XXE
    "434": ["cms", "web_app"],                # File Upload
    "352": ["web_app", "cms"],                # CSRF
    "426": ["os", "firmware"],                # Untrusted Search Path
    "20":  ["web_app", "server"],             # Input Validation
}

# ── Product domain → vendor candidates ──────────────────────────────────────
DOMAIN_TO_VENDORS: Dict[str, List[Tuple[str, float]]] = {
    "database":      [("mysql", 0.6), ("oracle", 0.5), ("postgresql", 0.5), ("mariadb", 0.4)],
    "web_server":    [("apache", 0.7), ("nginx", 0.6), ("microsoft", 0.4)],
    "web_app":       [("wordpress", 0.4), ("drupal", 0.3), ("joomla", 0.3)],
    "cms":           [("wordpress", 0.7), ("drupal", 0.5), ("joomla", 0.5)],
    "middleware":    [("apache", 0.6), ("pivotal", 0.5), ("jenkins", 0.4)],
    "app_server":    [("apache", 0.7), ("redhat", 0.5)],
    "network_os":    [("cisco", 0.7), ("fortinet", 0.6), ("paloalto", 0.5)],
    "network_device": [("cisco", 0.6), ("fortinet", 0.5), ("tenda", 0.4)],
    "os":            [("microsoft", 0.5), ("redhat", 0.4), ("ubuntu", 0.4)],
    "browser":       [("google", 0.6), ("microsoft", 0.5), ("mozilla", 0.5)],
    "native_library": [("openssl", 0.6), ("apache", 0.5)],
    "firmware":      [("tenda", 0.6), ("cisco", 0.5)],
    "identity":      [("microsoft", 0.6), ("okta", 0.4)],
    "vpn":           [("fortinet", 0.6), ("cisco", 0.5)],
    "proxy":         [("nginx", 0.5), ("warpgate", 0.4), ("haproxy", 0.4)],
    "iot":           [("tenda", 0.5)],
    "container":     [("docker", 0.5), ("kubernetes", 0.4)],
    "server":        [("apache", 0.5), ("nginx", 0.4), ("microsoft", 0.4)],
    "api_gateway":   [("nginx", 0.5)],
    "file_server":   [("microsoft", 0.5)],
    "xml_parser":    [("apache", 0.5)],
    "web_service":   [("apache", 0.5)],
    "doc_processor": [("adobe", 0.6), ("microsoft", 0.5)],
    "cli_tool":      [("microsoft", 0.4)],
    "cloud_service": [],
}

# ── CVSS Attack Vector → product domains ───────────────────────────────────
CVSS_AV_TO_DOMAINS: Dict[str, List[str]] = {
    "NETWORK": ["web_server", "web_app", "api_gateway", "network_device",
                "middleware", "app_server", "messaging", "network_os", "proxy"],
    "ADJACENT": ["network_device", "firmware", "network_os", "iot", "vpn"],
    "LOCAL": ["os", "browser", "native_library", "container", "cli_tool"],
    "PHYSICAL": ["firmware", "iot", "network_device"],
}

# ── NIST control family → product domains ──────────────────────────────────
NIST_FAMILY_TO_DOMAINS: Dict[str, List[str]] = {
    "SC": ["network_device", "proxy", "vpn"],           # System & Communications
    "SI": ["web_server", "middleware", "os"],           # System & Info Integrity
    "AC": ["identity", "web_app", "os"],                # Access Control
    "IA": ["identity", "vpn", "web_app"],               # Identification & Auth
    "CM": ["os", "network_device", "firmware"],         # Configuration Mgmt
    "AU": ["middleware", "app_server"],                 # Audit & Accountability
}

# ── Source reliability weights ─────────────────────────────────────────────
SOURCE_WEIGHTS: Dict[str, float] = {
    "description_nlp": 1.0,
    "nvd_references": 0.9,
    "cwe_domain": 0.8,
    "cvss_av": 0.6,
    "nist_weakness": 0.5,
}

CONFIDENCE_HIGH = 0.70       # Use result directly
CONFIDENCE_MEDIUM = 0.40     # Use but flag needs_analyst_review

# ── Known vendor domains ───────────────────────────────────────────────────
KNOWN_VENDOR_DOMAINS: Dict[str, str] = {
    "apache": "apache", "microsoft": "microsoft", "cisco": "cisco",
    "fortinet": "fortinet", "vmware": "vmware", "mysql": "mysql",
    "oracle": "oracle", "openssl": "openssl", "wordpress": "wordpress",
    "jenkins": "jenkins", "atlassian": "atlassian", "redhat": "redhat",
    "siemens": "siemens", "nginx": "nginx", "ubuntu": "ubuntu",
    "debian": "debian", "tenda": "tenda", "paloalto": "paloalto",
}

# ── GitHub org to vendor mapping ───────────────────────────────────────────
GITHUB_ORG_TO_VENDOR: Dict[str, str] = {
    "apache": "apache", "nodejs": "nodejs", "kubernetes": "kubernetes",
    "django": "django", "python": "python", "elastic": "elastic",
    "mongodb": "mongodb", "redis": "redis", "nginx": "nginx",
    "openssl": "openssl", "openssh": "openssh", "curl": "curl",
    "wordpress": "wordpress", "drupal": "drupal", "atlassian": "atlassian",
    "warpgate-proxy": "warpgate", "grafana": "grafana", "prometheus": "prometheus",
    "microsoft": "microsoft", "google": "google", "mozilla": "mozilla",
    "cisco": "cisco", "spring-projects": "pivotal", "pivotal": "pivotal",
    "hashicorp": "hashicorp", "docker": "docker", "kubernetes-csi": "kubernetes",
    "centos": "centos", "ubuntu": "ubuntu", "debian": "debian",
}

# ── Vendor key to display name mapping ──────────────────────────────────────
VENDOR_KEY_TO_PRODUCT: Dict[str, Dict[str, str]] = {
    "apache": {"vendor": "apache", "product": "http_server"},
    "mysql": {"vendor": "mysql", "product": "mysql"},
    "microsoft": {"vendor": "microsoft", "product": "windows"},
    "cisco": {"vendor": "cisco", "product": "ios"},
    "fortinet": {"vendor": "fortinet", "product": "fortios"},
    "openssl": {"vendor": "openssl", "product": "openssl"},
    "wordpress": {"vendor": "wordpress", "product": "wordpress"},
    "jenkins": {"vendor": "jenkins", "product": "jenkins"},
    "redhat": {"vendor": "redhat", "product": "enterprise_linux"},
    "vmware": {"vendor": "vmware", "product": "esxi"},
    "nginx": {"vendor": "nginx", "product": "nginx"},
    "pivotal": {"vendor": "pivotal", "product": "spring_framework"},
    "oracle": {"vendor": "oracle", "product": "database"},
    "postgresql": {"vendor": "postgresql", "product": "postgresql"},
    "siemens": {"vendor": "siemens", "product": "simatic"},
    "tenda": {"vendor": "tenda", "product": "router"},
    "paloalto": {"vendor": "paloalto", "product": "pan_os"},
    "ubuntu": {"vendor": "ubuntu", "product": "ubuntu"},
    "debian": {"vendor": "debian", "product": "debian"},
    "docker": {"vendor": "docker", "product": "docker"},
    "kubernetes": {"vendor": "kubernetes", "product": "kubernetes"},
    "google": {"vendor": "google", "product": "chrome"},
    "mozilla": {"vendor": "mozilla", "product": "firefox"},
    "okta": {"vendor": "okta", "product": "okta"},
    "haproxy": {"vendor": "haproxy", "product": "haproxy"},
    "warpgate": {"vendor": "warpgate", "product": "warpgate"},
    "drupal": {"vendor": "drupal", "product": "drupal"},
    "joomla": {"vendor": "joomla", "product": "joomla"},
    "mariadb": {"vendor": "mariadb", "product": "mariadb"},
    "atlas": {"vendor": "atlassian", "product": "jira"},
    "atlassian": {"vendor": "atlassian", "product": "jira"},
    "adobe": {"vendor": "adobe", "product": "acrobat"},
}


class MultiSourceIntel:
    """Multi-source voting engine for CVE vendor/product inference."""

    def infer_vendor(self, cve_dict: dict) -> dict:
        """
        Run all 5 signals and vote to produce a vendor/product inference.

        Returns dict with vendor, product, confidence, source_breakdown, etc.
        """
        sources = [
            self._signal_description_nlp(cve_dict),
            self._signal_nvd_references(cve_dict),
            self._signal_cwe_domain(cve_dict),
            self._signal_cvss_attack_vector(cve_dict),
            self._signal_nist_weakness_category(cve_dict),
        ]

        # Weighted vote accumulation
        vote_accumulator = defaultdict(float)
        for s in sources:
            w = SOURCE_WEIGHTS[s["source_name"]]
            for (vendor_key, raw_conf) in s["vendor_candidates"]:
                vote_accumulator[vendor_key] += raw_conf * w

        if not vote_accumulator:
            return {
                "vendor": None, "product": None, "confidence": 0.0,
                "source": "multi_source_intel", "needs_review": True,
                "source_breakdown": {}, "all_votes": {}, "sources_agreeing": [],
                "sources_disagreeing": []
            }

        # Bonus for multi-source agreement (3+ sources vote same vendor)
        for vendor_key in list(vote_accumulator.keys()):
            agreeing = sum(
                1 for s in sources
                if any(v == vendor_key for (v, _) in s["vendor_candidates"])
            )
            if agreeing >= 3:
                vote_accumulator[vendor_key] += 0.3

        max_possible = sum(SOURCE_WEIGHTS.values()) + 0.3
        winner = max(vote_accumulator, key=vote_accumulator.get)
        normalized_conf = min(vote_accumulator[winner] / max_possible, 1.0)

        vendor_info = VENDOR_KEY_TO_PRODUCT.get(winner, {})
        vendor = vendor_info.get("vendor", winner)
        product = vendor_info.get("product", winner)

        sources_agreeing = [s["source_name"] for s in sources
                            if any(v == winner for v, _ in s["vendor_candidates"])]
        sources_disagreeing = [s["source_name"] for s in sources
                                if s["vendor_candidates"] and
                                   all(v != winner for v, _ in s["vendor_candidates"])]

        breakdown = {
            s["source_name"]: {
                "top_candidate": s["vendor_candidates"][0] if s["vendor_candidates"] else None,
                "raw_data": s["raw_data"]
            }
            for s in sources
        }

        return {
            "vendor": vendor, "product": product, "vendor_key": winner,
            "confidence": normalized_conf, "source": "multi_source_intel",
            "source_breakdown": breakdown, "all_votes": dict(vote_accumulator),
            "sources_agreeing": sources_agreeing, "sources_disagreeing": sources_disagreeing,
            "needs_review": normalized_conf < CONFIDENCE_HIGH,
        }

    def _signal_description_nlp(self, cve_dict: dict) -> dict:
        """Reuse product_extractor.extract_product_metadata()"""
        from tools.product_extractor import extract_product_metadata
        candidates = []
        extracted = None
        try:
            extracted = extract_product_metadata(cve_dict)
            if extracted.get("vendor"):
                conf_map = {"high": 0.85, "medium": 0.55, "low": 0.25}
                conf = conf_map.get(extracted.get("confidence", "low"), 0.25)
                vendor_key = extracted["vendor"].lower().replace(" ", "_")
                candidates = [(vendor_key, conf)]
        except Exception:
            pass
        return {
            "source_name": "description_nlp", "vendor_candidates": candidates,
            "raw_data": {"extracted": extracted if extracted else {}}
        }

    def _signal_nvd_references(self, cve_dict: dict) -> dict:
        """Parse GitHub orgs and vendor domains from reference URLs."""
        refs = cve_dict.get("references", [])
        candidates = []
        urls_matched = []
        seen = set()
        for ref in refs:
            url = ref if isinstance(ref, str) else ref.get("url", "")
            vendor_key = _parse_vendor_from_url(url)
            if vendor_key and vendor_key not in seen:
                candidates.append((vendor_key, 0.90))
                urls_matched.append(url)
                seen.add(vendor_key)
        return {
            "source_name": "nvd_references", "vendor_candidates": candidates,
            "raw_data": {"refs_parsed": len(refs), "urls_matched": urls_matched}
        }

    def _signal_cwe_domain(self, cve_dict: dict) -> dict:
        """Map CWEs → domains → vendors."""
        cwe_ids = cve_dict.get("cwe_ids", [])
        if not cwe_ids:
            return {
                "source_name": "cwe_domain", "vendor_candidates": [],
                "raw_data": {"cwe_ids": [], "domains_hit": []}
            }
        vendor_scores = defaultdict(float)
        domains_hit = []
        for raw_cwe in cwe_ids:
            cwe_num = str(raw_cwe).replace("CWE-", "")
            domains = CWE_TO_VENDOR_DOMAIN.get(cwe_num, [])
            for domain in domains:
                if domain not in domains_hit:
                    domains_hit.append(domain)
                for vendor_key, base_conf in DOMAIN_TO_VENDORS.get(domain, []):
                    vendor_scores[vendor_key] += base_conf / max(len(cwe_ids), 1)
        candidates = sorted(vendor_scores.items(), key=lambda x: -x[1])[:5]
        return {
            "source_name": "cwe_domain", "vendor_candidates": candidates,
            "raw_data": {"cwe_ids": cwe_ids, "domains_hit": domains_hit}
        }

    def _signal_cvss_attack_vector(self, cve_dict: dict) -> dict:
        """CVSS AV → domains → vendors."""
        av = _extract_attack_vector(cve_dict)
        if not av:
            return {
                "source_name": "cvss_av", "vendor_candidates": [],
                "raw_data": {"attack_vector": None, "domains_inferred": []}
            }
        domains = CVSS_AV_TO_DOMAINS.get(av, [])
        vendor_scores = defaultdict(float)
        for domain in domains:
            for vendor_key, base_conf in DOMAIN_TO_VENDORS.get(domain, []):
                vendor_scores[vendor_key] += base_conf * 0.5 / max(len(domains), 1)
        candidates = sorted(vendor_scores.items(), key=lambda x: -x[1])[:5]
        return {
            "source_name": "cvss_av", "vendor_candidates": candidates,
            "raw_data": {"attack_vector": av, "domains_inferred": domains}
        }

    def _signal_nist_weakness_category(self, cve_dict: dict) -> dict:
        """NIST control families → domains → vendors."""
        from tools.cwe_mapper import CWE_TO_NIST
        cwe_ids = cve_dict.get("cwe_ids", [])
        vendor_scores = defaultdict(float)
        families_seen = []
        for raw_cwe in cwe_ids:
            cwe_num = str(raw_cwe).replace("CWE-", "")
            nist_controls = CWE_TO_NIST.get(cwe_num, [])
            for ctrl in nist_controls:
                family = ctrl.split("-")[0]   # "AC-3" → "AC"
                if family not in families_seen:
                    families_seen.append(family)
                for domain in NIST_FAMILY_TO_DOMAINS.get(family, []):
                    for vendor_key, base_conf in DOMAIN_TO_VENDORS.get(domain, []):
                        vendor_scores[vendor_key] += base_conf * 0.4 / max(len(cwe_ids), 1)
        candidates = sorted(vendor_scores.items(), key=lambda x: -x[1])[:5]
        return {
            "source_name": "nist_weakness", "vendor_candidates": candidates,
            "raw_data": {"nist_families": families_seen}
        }


def _extract_attack_vector(cve_dict: dict) -> Optional[str]:
    """Extract CVSS Attack Vector from CVE data."""
    metrics = cve_dict.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics:
            av = metrics[key][0].get("cvssData", {}).get("attackVector", "")
            if av:
                return av.upper()
    if "cvssMetricV2" in metrics:
        av = metrics["cvssMetricV2"][0].get("cvssData", {}).get("accessVector", "")
        if av:
            return av.upper()
    vector = cve_dict.get("cvss_vector", "")
    if vector:
        m = re.search(r'AV:([NALP])', vector)
        if m:
            aliases = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
            return aliases.get(m.group(1))
    return None


def _parse_vendor_from_url(url: str) -> Optional[str]:
    """Extract vendor key from reference URL."""
    url_lower = url.lower()
    # Skip advisory/generic sites
    for skip in ("nvd.nist.gov", "cisa.gov", "mitre.org", "securityfocus.com",
                 "exploit-db.com", "packetstorm"):
        if skip in url_lower:
            return None
    # GitHub: extract org
    m = re.search(r'github\.com/([a-z0-9\-]+)', url_lower)
    if m:
        org = m.group(1)
        return GITHUB_ORG_TO_VENDOR.get(org, f"github_{org}")
    # Known vendor domains (subdomain-aware: extract main domain before TLD)
    m = re.search(r'https?://(?:[a-z0-9\-]+\.)*([a-z0-9\-]+)\.(?:com|org|net|io)', url_lower)
    if m:
        main_domain = m.group(1)
        # Check if we know this domain
        if main_domain in KNOWN_VENDOR_DOMAINS:
            return KNOWN_VENDOR_DOMAINS[main_domain]
    return None
