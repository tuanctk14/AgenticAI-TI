"""
tools/cve_parser.py - CPE-first architecture for analyst-grade CVE asset matching

Hierarchy:
1. CPE extraction (gold source - structured, machine-readable)
2. Software normalization (handle aliases: apache2 → apache:http_server)
3. Fuzzy semantic matching (for internal asset correlation)
4. NER/LLM fallback (for CVEs without CPE)
5. Description parsing (last resort - noisy, inconsistent)
"""
import re
from typing import Dict, List, Optional, Tuple
from packaging import version as pkg_version

# Software normalization layer (ANALYST-GRADE)
SOFTWARE_NORMALIZATION = {
    # Apache family
    "apache2": "apache:http_server",
    "httpd": "apache:http_server",
    "apache http server": "apache:http_server",
    "apache httpd": "apache:http_server",
    # Tomcat family
    "tomcat": "apache:tomcat",
    # PHP
    "php": "php:php",
    # MySQL
    "mysql": "mysql:mysql",
    "mariadb": "mariadb:mariadb",
    # OpenSSL
    "openssl": "openssl:openssl",
    # WordPress
    "wordpress": "wordpress:wordpress",
    "wordpress plugin": "wordpress:wordpress",
    # Spring
    "spring framework": "pivotal:spring_framework",
    "spring boot": "pivotal:spring_boot",
    # Cisco
    "cisco asa": "cisco:adaptive_security_appliance",
    "cisco ios": "cisco:ios",
    "cisco ios-xe": "cisco:ios_xe",
    # Fortinet
    "fortios": "fortinet:fortios",
    "fortigate": "fortinet:fortigate",
    # VMware
    "vmware esxi": "vmware:esxi",
    "esxi": "vmware:esxi",
    "vmware vcenter": "vmware:vcenter",
    # Microsoft
    "microsoft exchange": "microsoft:exchange_server",
    "exchange server": "microsoft:exchange_server",
    "microsoft windows": "microsoft:windows",
}

class CPEParser:
    """Extract and normalize CPE from CVE configurations (NVD structure)"""

    @staticmethod
    def extract_cpe_from_configurations(configurations: List[Dict]) -> List[str]:
        """
        Extract CPEs from NVD configurations structure

        NVD format:
        configurations[].nodes[].cpeMatch[].cpe23Uri
        """
        cpes = []
        if not configurations:
            return cpes

        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches:
                    cpe_uri = match.get("cpe23Uri", "")
                    if cpe_uri and cpe_uri not in cpes:
                        cpes.append(cpe_uri)

        return cpes

    @staticmethod
    def parse_cpe_uri(cpe_uri: str) -> Dict[str, str]:
        """
        Parse CPE 2.3 URI format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

        Returns: {vendor, product, version, part}
        """
        if not cpe_uri.startswith("cpe:2.3:"):
            return {}

        parts = cpe_uri.split(":")
        if len(parts) < 6:
            return {}

        return {
            "part": parts[2],  # a (application), o (operating system), h (hardware)
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5],
            "full_cpe": cpe_uri,
        }

    @staticmethod
    def normalize_software_id(vendor: str, product: str) -> str:
        """Convert vendor:product to normalized software ID"""
        normalized = f"{vendor.lower()}:{product.lower()}".replace(" ", "_")
        return normalized


class DescriptionParser:
    """Parse CVE description (fallback when CPE unavailable - less reliable)"""

    # Application patterns with normalized software IDs
    APP_PATTERNS = {
        "apache:http_server": r'apache\s+(?:http\s+)?server|httpd|apache2',
        "apache:log4j": r'apache\s+log4j|log4j[2-9]?',
        "apache:tomcat": r'apache\s+tomcat|tomcat',
        "mysql:mysql": r'mysql',
        "openssl:openssl": r'openssl',
        "wordpress:wordpress": r'wordpress',
        "spring:framework": r'spring\s+(?:framework|boot)',
        "cisco:ios": r'cisco\s+ios',
        "cisco:asa": r'cisco\s+(?:adaptive\s+security\s+)?appliance|cisco\s+asa',
        "fortinet:fortios": r'fortinet\s+fortios|fortigate|fortigate',
        "vmware:esxi": r'vmware\s+esxi|esxi',
        "microsoft:exchange": r'microsoft\s+exchange|exchange\s+server',
    }

    @staticmethod
    def extract_product_info(description: str) -> Dict[str, Optional[str]]:
        """
        Use simple keyword matching to identify product
        Returns: {vendor, product, version, normalized_id}
        """
        desc_lower = description.lower()
        result = {
            "vendor": None,
            "product": None,
            "version": None,
            "normalized_id": None,
        }

        # Try to match known products
        for normalized_id, pattern in DescriptionParser.APP_PATTERNS.items():
            if re.search(pattern, desc_lower):
                vendor, product = normalized_id.split(":")
                result["vendor"] = vendor
                result["product"] = product
                result["normalized_id"] = normalized_id
                break

        # Extract version if not found
        if not result["version"]:
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?(?:-\w+)?)', description)
            if version_match:
                result["version"] = version_match.group(1)

        return result


def normalize_software_name(software_name: str) -> Optional[str]:
    """
    Normalize software name to standard format
    e.g., "apache2" → "apache:http_server"
    """
    sw_lower = software_name.lower()

    # Direct lookup
    if sw_lower in SOFTWARE_NORMALIZATION:
        return SOFTWARE_NORMALIZATION[sw_lower]

    # Substring match
    for key, normalized in SOFTWARE_NORMALIZATION.items():
        if key in sw_lower or sw_lower in key:
            return normalized

    return None


def parse_cve_metadata(cve_dict: dict) -> dict:
    """
    ANALYST-GRADE CVE asset matching using CPE-first architecture

    Inference hierarchy:
    1. CPE extraction (gold source from NVD configurations)
    2. Software normalization (handle aliases)
    3. Description parsing (fallback when CPE unavailable)

    Returns: {
        cve_id, vendor, product, version,
        normalized_software_id,
        affected_os, source
    }
    """
    cve_id = cve_dict.get("id", "").upper()
    description = cve_dict.get("description", "").strip()
    configurations = cve_dict.get("configurations", [])

    result = {
        "cve_id": cve_id,
        "vendor": None,
        "product": None,
        "version": None,
        "normalized_software_id": None,
        "affected_os": None,
        "source": "none",  # gold_cpe, inference, fallback
    }

    # ────────────────────────────────────────────────────────────
    # PHASE 1: CPE EXTRACTION (GOLD SOURCE)
    # ────────────────────────────────────────────────────────────
    cpes = CPEParser.extract_cpe_from_configurations(configurations)
    if cpes:
        cpe_parsed = CPEParser.parse_cpe_uri(cpes[0])
        if cpe_parsed:
            result["vendor"] = cpe_parsed.get("vendor")
            result["product"] = cpe_parsed.get("product")
            result["version"] = cpe_parsed.get("version")
            result["normalized_software_id"] = CPEParser.normalize_software_id(
                cpe_parsed.get("vendor", ""),
                cpe_parsed.get("product", "")
            )
            result["source"] = "gold_cpe"
            return result

    # ────────────────────────────────────────────────────────────
    # PHASE 2: DESCRIPTION PARSING (FALLBACK)
    # ────────────────────────────────────────────────────────────
    if description:
        product_info = DescriptionParser.extract_product_info(description)
        if product_info["vendor"]:
            result["vendor"] = product_info["vendor"]
            result["product"] = product_info["product"]
            result["version"] = product_info["version"]
            result["normalized_software_id"] = product_info["normalized_id"]
            result["source"] = "description_inference"
            return result

        # Extract version as last resort
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', description)
        if version_match:
            result["version"] = version_match.group(1)

    # ────────────────────────────────────────────────────────────
    # PHASE 3: OS/PLATFORM DETECTION
    # ────────────────────────────────────────────────────────────
    if description:
        desc_lower = description.lower()
        os_patterns = {
            "Windows": r'windows',
            "Linux": r'linux|ubuntu|centos|debian|red hat',
            "macOS": r'mac\s*os|macos|darwin',
            "All": r'all\s+(?:platforms?|systems?|operating\s+systems?)',
        }
        for os_name, os_regex in os_patterns.items():
            if re.search(os_regex, desc_lower):
                result["affected_os"] = os_name
                break

    return result


def compare_versions(device_version: str, vulnerable_max: str, vulnerable_min: str = None) -> bool:
    """
    Compare versions to check if device is vulnerable.

    Returns True if device_version is within vulnerable range:
    - If vulnerable_min: vulnerable_min <= device_version <= vulnerable_max
    - Else: device_version <= vulnerable_max

    Returns False if version cannot be parsed (safe assumption)
    """
    try:
        dev_ver = pkg_version.parse(device_version)
        max_ver = pkg_version.parse(vulnerable_max)

        # Check if device version <= max vulnerable version
        if dev_ver > max_ver:
            return False

        # If min version specified, check lower bound
        if vulnerable_min:
            min_ver = pkg_version.parse(vulnerable_min)
            if dev_ver < min_ver:
                return False

        return True
    except Exception:
        # If version parsing fails, be conservative and don't match
        return False


def match_app_in_device(
    cve_metadata: dict,
    device_software: list
) -> Dict[str, any]:
    """
    ANALYST-GRADE asset matching using normalized software IDs

    Uses software normalization layer to handle aliases:
    - "apache2" → "apache:http_server"
    - "httpd" → "apache:http_server"
    - "Exchange Server" → "microsoft:exchange_server"

    Returns: {
        matched: bool,
        software_name: str or None,
        device_version: str or None,
        normalized_id: str or None,
        match_type: "exact_normalized", "keyword_fallback", "none"
    }
    """
    normalized_cve_id = cve_metadata.get("normalized_software_id")
    cve_vendor = cve_metadata.get("vendor")
    cve_version = cve_metadata.get("version")

    # ────────────────────────────────────────────────────────────
    # PHASE 1: EXACT NORMALIZED ID MATCHING
    # ────────────────────────────────────────────────────────────
    if normalized_cve_id:
        for software in device_software:
            sw_name = software.get("name", "")
            normalized_sw_id = normalize_software_name(sw_name)

            if normalized_sw_id == normalized_cve_id:
                return {
                    "matched": True,
                    "software_name": sw_name,
                    "device_version": software.get("version"),
                    "normalized_id": normalized_cve_id,
                    "match_type": "exact_normalized",
                }

    # ────────────────────────────────────────────────────────────
    # PHASE 2: KEYWORD FALLBACK
    # ────────────────────────────────────────────────────────────
    keywords = [cve_vendor, cve_metadata.get("product")]
    keywords = [k for k in keywords if k]

    for keyword in keywords:
        if not keyword:
            continue

        for software in device_software:
            sw_name = software.get("name", "").lower()
            if keyword.lower() in sw_name:
                return {
                    "matched": True,
                    "software_name": software.get("name"),
                    "device_version": software.get("version"),
                    "normalized_id": None,
                    "match_type": "keyword_fallback",
                }

    return {
        "matched": False,
        "software_name": None,
        "device_version": None,
        "normalized_id": None,
        "match_type": "none",
    }


def match_app_in_device_legacy(app_keywords: list, device_software: list) -> dict:
    """
    DEPRECATED: Legacy keyword-only matching (for backwards compatibility)
    Use match_app_in_device() with normalized software IDs instead

    Try to match CVE app keywords with device installed software.

    Returns dict:
    {
        "matched": True/False,
        "software_name": matched software name from device,
        "device_version": version of matched software
    }
    """
    for keyword in app_keywords:
        for software in device_software:
            sw_name = software.get("name", "").lower()
            if keyword.lower() in sw_name:
                return {
                    "matched": True,
                    "software_name": software.get("name"),
                    "device_version": software.get("version")
                }

    return {
        "matched": False,
        "software_name": None,
        "device_version": None
    }
