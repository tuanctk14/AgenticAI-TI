"""
tools/cve_parser.py - CPE-first architecture for analyst-grade CVE asset matching

Hierarchy:
1. CPE extraction (gold source - structured, machine-readable)
2. Software normalization (handle aliases: apache2 → apache:http_server)
3. Product extraction (regex patterns + entity matching when CPE unavailable)
4. Confidence scoring (high/medium/low with manual review flags)
5. Description parsing (last resort - noisy, inconsistent)
"""
import re
from typing import Dict, List, Optional, Tuple
from packaging import version as pkg_version
from tools.product_extractor import extract_product_metadata, match_confidence_score

# Software normalization layer (ANALYST-GRADE)
SOFTWARE_NORMALIZATION = {
    # Apache family
    "apache2": "apache:http_server",
    "httpd": "apache:http_server",
    "apache http server": "apache:http_server",
    "apache httpd": "apache:http_server",
    "apache": "apache:http_server",
    # Apache products
    "apache log4j": "apache:log4j",
    "log4j": "apache:log4j",
    "log4j2": "apache:log4j",
    "apache activemq": "apache:activemq",
    "activemq": "apache:activemq",
    # Tomcat family
    "tomcat": "apache:tomcat",
    # Tenda Router
    "tenda ac6": "tenda:ac6",
    "tenda ac 6": "tenda:ac6",
    "tenda router": "tenda:router",
    "tenda": "tenda:router",
    # PHP
    "php": "php:php",
    # MySQL & Databases
    "mysql": "mysql:mysql",
    "mysql server": "mysql:mysql",
    "mariadb": "mariadb:mariadb",
    # OpenSSL & SSH
    "openssl": "openssl:openssl",
    "openssh": "openssh:openssh",
    # WordPress
    "wordpress": "wordpress:wordpress",
    "wordpress plugin download from files": "wordpress:wordpress",
    "wordpress plugin": "wordpress:wordpress",
    # Spring Framework
    "spring framework": "pivotal:spring_framework",
    "spring boot": "pivotal:spring_boot",
    "spring data": "pivotal:spring_framework",
    "spring": "pivotal:spring_framework",
    # Cisco
    "cisco asa": "cisco:asa",
    "cisco ios": "cisco:ios",
    "cisco ios-xe": "cisco:ios_xe",
    # Fortinet
    "fortios": "fortinet:fortios",
    "fortigate": "fortinet:fortigate",
    "fortinet": "fortinet:fortios",
    # VMware
    "vmware esxi": "vmware:esxi",
    "esxi": "vmware:esxi",
    "vmware vcenter": "vmware:vcenter",
    # Microsoft
    "microsoft exchange": "microsoft:exchange_server",
    "exchange server": "microsoft:exchange_server",
    "exchange": "microsoft:exchange_server",
    "microsoft windows": "microsoft:windows",
    "microsoft office": "microsoft:office",
    # Java & Infra
    "jenkins": "jenkins:jenkins",
    "jenkins ci": "jenkins:jenkins",
    "atlassian confluence": "atlassian:confluence",
    "confluence": "atlassian:confluence",
    "atlassian jira": "atlassian:jira",
    "jira": "atlassian:jira",
    # Browser & Desktop
    "chrome": "google:chrome",
    "adobe acrobat": "adobe:acrobat",
    "openjdk": "openjdk:openjdk",
}

class CPEParser:
    """Extract and normalize CPE from CVE configurations (NVD structure)"""

    @staticmethod
    def extract_cpe_from_configurations(configurations: List[Dict]) -> List[str]:
        """
        Extract CPEs from NVD configurations structure

        NVD API v2.0 format:
        configurations[].nodes[].cpeMatch[].criteria (CPE string)
        or legacy:
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
                    # Try 'criteria' first (NVD API v2.0), then 'cpe23Uri' (legacy)
                    cpe_uri = match.get("criteria", "") or match.get("cpe23Uri", "")
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
    # Ordered by priority (more specific patterns first)
    APP_PATTERNS = {
        # Apache products (specific first - MORE RESTRICTIVE to avoid false positives)
        "apache:log4j": r'apache\s+log4j2?|^log4j|log4j\s+library',
        "apache:activemq": r'apache\s+activemq|activemq\s+broker|activemq\s+message',
        "apache:http_server": r'apache\s+(?:http|web|server)|apache(?:\s+)?httpd|apache2\b',
        "apache:tomcat": r'apache\s+tomcat|tomcat\s+server',

        # Router & Network Hardware
        "tenda:ac6": r'tenda\s+(?:ac6|ac\s*6)',
        "tenda:router": r'tenda\s+(?:router|gateway)',

        # Middleware & Frameworks
        "spring:framework": r'spring\s+(?:framework|boot|data)',
        "pivotal:spring": r'spring\s+(?:framework|boot)',

        # Databases
        "mysql:mysql": r'mysql(?:\s+server)?',
        "openssl:openssl": r'openssl(?:\s+ssl)?',

        # CMS & Content
        "wordpress:wordpress": r'wordpress(?:\s+plugin)?|wordpress\s+core',

        # Network & Security
        "cisco:ios": r'cisco\s+ios(?:-?xe)?',
        "cisco:asa": r'cisco\s+(?:adaptive\s+security\s+)?appliance|cisco\s+asa',
        "fortinet:fortios": r'fortinet\s+fortios|fortigate|fortios',
        "vmware:esxi": r'vmware\s+esxi|esxi(?:\s+hypervisor)?',
        "microsoft:exchange": r'microsoft\s+exchange|exchange\s+server',

        # Java/Infra
        "jenkins:jenkins": r'jenkins(?:\s+ci)?|jenkins(?:\s+automation)?',
        "atlassian:confluence": r'atlassian\s+confluence|confluence',
        "atlassian:jira": r'atlassian\s+jira|jira',
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
    cwe_ids = cve_dict.get("cwe_ids", [])

    result = {
        "cve_id": cve_id,
        "vendor": None,
        "product": None,
        "component": None,  # plugin/module/extension name
        "component_type": None,  # plugin, module, library, extension
        "version": None,
        "normalized_software_id": None,
        "affected_os": None,
        "cwe_ids": cwe_ids,
        "source": "none",  # gold_cpe, component, pattern, inference, fallback
    }

    # ────────────────────────────────────────────────────────────
    # PHASE 1: CPE EXTRACTION (GOLD SOURCE)
    # ────────────────────────────────────────────────────────────
    cpes = CPEParser.extract_cpe_from_configurations(configurations)
    if cpes:
        # For CVEs with multiple CPEs (e.g., library vulnerabilities),
        # try to find the primary/library CPE by matching description keywords
        selected_cpe = None
        desc_lower = description.lower()

        # Priority 1: Try to match description keywords to find the vulnerable component
        for cpe in cpes:
            parsed = CPEParser.parse_cpe_uri(cpe)
            product = parsed.get("product", "").lower().replace("_", " ")
            vendor = parsed.get("vendor", "").lower()

            # Check if product name appears prominently in description
            if product in desc_lower or vendor in desc_lower:
                selected_cpe = cpe
                break

        # Priority 2: Fall back to first CPE if no match found
        if not selected_cpe:
            selected_cpe = cpes[0]

        cpe_parsed = CPEParser.parse_cpe_uri(selected_cpe)
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
    # PHASE 2: PRODUCT EXTRACTION (ANALYST-GRADE INFERENCE)
    # ────────────────────────────────────────────────────────────
    if description:
        extracted = extract_product_metadata(cve_dict)
        if extracted.get("vendor") and extracted.get("product"):
            result["vendor"] = extracted["vendor"]
            result["product"] = extracted["product"]
            result["component"] = extracted.get("component")
            result["component_type"] = extracted.get("component_type")
            result["version"] = extracted.get("version")
            result["normalized_software_id"] = f"{extracted['vendor']}:{extracted['product']}"
            result["source"] = f"product_extraction_{extracted['source']}"
            result["extraction_confidence"] = extracted["confidence"]
            result["needs_analyst_review"] = extracted["needs_review"]
            result["extraction_aliases"] = extracted["aliases"]
            return result

    # ────────────────────────────────────────────────────────────
    # PHASE 3: LEGACY DESCRIPTION PARSING (FALLBACK)
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
    # PHASE 4: OS/PLATFORM DETECTION
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
    # PHASE 2: KEYWORD FALLBACK (MORE RESTRICTIVE)
    # Only match if vendor+product keywords both appear or product appears prominently
    # ────────────────────────────────────────────────────────────
    cve_product = cve_metadata.get("product", "").lower()
    cve_vendor_lower = cve_vendor.lower() if cve_vendor else ""

    for software in device_software:
        sw_name_lower = software.get("name", "").lower()
        sw_normalized = normalize_software_name(software.get("name", ""))

        # Only do keyword fallback if we have high confidence:
        # 1. Product keyword clearly appears (not just vendor)
        # 2. OR product keyword + vendor keyword both appear
        product_in_name = cve_product and cve_product in sw_name_lower
        both_in_name = cve_vendor_lower and cve_product and (cve_vendor_lower in sw_name_lower and cve_product in sw_name_lower)

        # Avoid false positives: if vendor matches but product doesn't, skip
        # e.g., "apache" vendor + "log4j" product should NOT match "Apache HTTP Server"
        if both_in_name or (product_in_name and len(cve_product) > 2):
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
