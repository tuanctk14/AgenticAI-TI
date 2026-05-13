"""
tools/cve_parser.py - CPE-first architecture for analyst-grade CVE asset matching

Hierarchy:
1. CPE extraction (gold source - structured, machine-readable)
2. Software normalization (handle aliases: apache2 → apache:http_server)
3. Product extraction (regex patterns + entity matching when CPE unavailable)
4. Confidence scoring (high/medium/low with manual review flags)
5. Description parsing (last resort - noisy, inconsistent)
6. Date validation (sanity check for published date)
"""
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from packaging import version as pkg_version
from tools.product_extractor import extract_product_metadata, match_confidence_score
from tools.date_validator import DateValidator

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
    """Extract and normalize CPE from CVE configurations with version range support (NVD structure)"""

    @staticmethod
    def extract_cpe_from_configurations(configurations: List[Dict]) -> List[Dict]:
        """
        Extract CPE entries with version range data from NVD configurations.

        Returns list of dict with: {
            cpe_uri, vendor, product, version,
            version_start_including, version_start_excluding,
            version_end_including, version_end_excluding,
            vulnerable, normalized_id
        }
        """
        cpe_entries = []
        if not configurations:
            return cpe_entries

        seen = set()
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches:
                    cpe_uri = match.get("criteria", "") or match.get("cpe23Uri", "")
                    if not cpe_uri or cpe_uri in seen:
                        continue
                    seen.add(cpe_uri)

                    parsed = CPEParser.parse_cpe_uri(cpe_uri)
                    if not parsed:
                        continue

                    entry = {
                        "cpe_uri": cpe_uri,
                        "vendor": parsed.get("vendor"),
                        "product": parsed.get("product"),
                        "version": parsed.get("version"),
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                        "vulnerable": match.get("vulnerable", True),
                        "normalized_id": CPEParser.normalize_software_id(
                            parsed.get("vendor", ""),
                            parsed.get("product", "")
                        )
                    }
                    cpe_entries.append(entry)

        return cpe_entries

    @staticmethod
    def extract_cpe_uris_simple(configurations: List[Dict]) -> List[str]:
        """
        Extract just CPE URI strings (for backward compatibility).
        Returns list of CPE URI strings.
        """
        cpes = []
        cpe_entries = CPEParser.extract_cpe_from_configurations(configurations)
        for entry in cpe_entries:
            if entry.get("cpe_uri") and entry["cpe_uri"] not in cpes:
                cpes.append(entry["cpe_uri"])
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
        "date_valid": True,  # CVE date sanity check
        "date_warnings": [],  # Date validation warnings
    }

    # ────────────────────────────────────────────────────────────
    # DATE VALIDATION (SANITY CHECK)
    # ────────────────────────────────────────────────────────────
    published_date = cve_dict.get("published_date")
    if published_date:
        date_validation = DateValidator.validate_published_date(cve_id, published_date)
        result["date_valid"] = date_validation["is_valid"]
        result["date_warnings"].extend(date_validation["errors"])
        result["date_warnings"].extend(date_validation["warnings"])


    # ────────────────────────────────────────────────────────────
    # PHASE 1: CPE EXTRACTION (GOLD SOURCE)
    # ────────────────────────────────────────────────────────────
    cpe_entries = CPEParser.extract_cpe_from_configurations(configurations)
    if cpe_entries:
        # Store ALL CPE entries for multi-CPE matching
        result["cpe_entries"] = cpe_entries

        # For return data, select primary CPE by description matching
        selected_entry = None
        desc_lower = description.lower()

        # Priority 1: Try to match description keywords to find the vulnerable component
        for entry in cpe_entries:
            product = entry.get("product", "").lower().replace("_", " ")
            vendor = entry.get("vendor", "").lower()

            # Check if product name appears prominently in description
            if product in desc_lower or vendor in desc_lower:
                selected_entry = entry
                break

        # Priority 2: Fall back to first CPE if no match found
        if not selected_entry:
            selected_entry = cpe_entries[0]

        if selected_entry:
            result["vendor"] = selected_entry.get("vendor")
            result["product"] = selected_entry.get("product")
            result["version"] = selected_entry.get("version")
            result["version_start_including"] = selected_entry.get("version_start_including")
            result["version_start_excluding"] = selected_entry.get("version_start_excluding")
            result["version_end_including"] = selected_entry.get("version_end_including")
            result["version_end_excluding"] = selected_entry.get("version_end_excluding")
            result["normalized_software_id"] = selected_entry.get("normalized_id")
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
            # For components, use vendor:component as normalized ID; otherwise vendor:product
            if extracted.get("component"):
                result["normalized_software_id"] = f"{extracted['vendor']}:{extracted['component']}"
            else:
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


def compare_versions(
    device_version: str,
    vulnerable_max: str = None,
    vulnerable_min: str = None,
    version_end_excluding: str = None,
    version_end_including: str = None,
    version_start_including: str = None,
    version_start_excluding: str = None,
) -> bool:
    """
    Compare versions against CPE version range to check if device is vulnerable.

    Priority order (from CPE official range to legacy parameters):
    1. CPE version range: version_end_excluding, version_end_including,
       version_start_including, version_start_excluding
    2. Legacy: vulnerable_max, vulnerable_min

    Returns True if device_version is within vulnerable range.
    Returns False if version cannot be parsed (conservative).
    """
    try:
        dev_ver = pkg_version.parse(device_version)

        # Phase 1: Use CPE version range if available
        if version_end_excluding or version_end_including or version_start_including or version_start_excluding:
            # Check upper bound
            if version_end_excluding:
                if dev_ver >= pkg_version.parse(version_end_excluding):
                    return False
            if version_end_including:
                if dev_ver > pkg_version.parse(version_end_including):
                    return False

            # Check lower bound
            if version_start_including:
                if dev_ver < pkg_version.parse(version_start_including):
                    return False
            if version_start_excluding:
                if dev_ver <= pkg_version.parse(version_start_excluding):
                    return False

            return True

        # Phase 2: Fallback to legacy vulnerable_max/vulnerable_min
        if vulnerable_max:
            max_ver = pkg_version.parse(vulnerable_max)
            if dev_ver > max_ver:
                return False

            if vulnerable_min:
                min_ver = pkg_version.parse(vulnerable_min)
                if dev_ver < min_ver:
                    return False

            return True

        # If no version range specified, cannot determine vulnerability
        return False
    except Exception:
        return False


def match_app_in_device(
    cve_metadata: dict,
    device_software: list,
    device: dict = None
) -> Dict[str, any]:
    """
    ANALYST-GRADE asset matching using normalized software IDs + component detection

    Hierarchy:
    1. Component matching (exact plugin/module version match: 95% confidence)
    2. Platform matching (WordPress core version match: 70% confidence)
    3. Normalized ID matching (e.g., apache:http_server: 80% confidence)
    4. Keyword fallback (e.g., partial name match: 50% confidence)

    Returns: {
        matched: bool,
        software_name: str or None,
        device_version: str or None,
        normalized_id: str or None,
        match_type: "exact_component", "platform_match", "exact_normalized", "keyword_fallback", "none",
        confidence: 0-100,
        component: str or None,
        component_type: str or None
    }
    """
    normalized_cve_id = cve_metadata.get("normalized_software_id")
    cve_vendor = cve_metadata.get("vendor")
    cve_version = cve_metadata.get("version")
    cve_component = cve_metadata.get("component")
    cve_component_type = cve_metadata.get("component_type")

    # ────────────────────────────────────────────────────────────
    # PHASE 0: COMPONENT MATCHING (HIGHEST CONFIDENCE)
    # For CMS plugins/modules (WordPress, Drupal, Joomla)
    # ────────────────────────────────────────────────────────────
    if device and cve_component and cve_component_type == "plugin":
        # Check platform first
        platform = device.get("platform", {})
        platform_name = platform.get("name", "").lower() if platform else ""

        if platform_name == cve_vendor.lower():
            # Check plugins array
            plugins = device.get("plugins", [])
            for plugin in plugins:
                plugin_name = plugin.get("name", "").lower()
                plugin_version = plugin.get("version")

                if plugin_name == cve_component.lower():
                    if cve_version and compare_versions(plugin_version, cve_version):
                        return {
                            "matched": True,
                            "software_name": f"{cve_vendor}:{cve_component}",
                            "device_version": plugin_version,
                            "normalized_id": f"{cve_vendor}:{cve_component}",
                            "match_type": "exact_component",
                            "confidence": 95,
                            "component": cve_component,
                            "component_type": "plugin"
                        }
                    else:
                        return {
                            "matched": True,
                            "software_name": f"{cve_vendor}:{cve_component}",
                            "device_version": plugin_version,
                            "normalized_id": f"{cve_vendor}:{cve_component}",
                            "match_type": "exact_component",
                            "confidence": 85,
                            "component": cve_component,
                            "component_type": "plugin"
                        }

    # ────────────────────────────────────────────────────────────
    # PHASE 0.5: PLATFORM MATCHING (WordPress core version)
    # ────────────────────────────────────────────────────────────
    if device and cve_vendor and cve_vendor.lower() in ["wordpress", "drupal", "joomla"]:
        platform = device.get("platform", {})
        platform_name = platform.get("name", "").lower() if platform else ""

        if platform_name == cve_vendor.lower():
            platform_version = platform.get("version")
            if platform_version and cve_version and compare_versions(platform_version, cve_version):
                return {
                    "matched": True,
                    "software_name": cve_vendor,
                    "device_version": platform_version,
                    "normalized_id": f"{cve_vendor}:{cve_vendor}",
                    "match_type": "platform_match",
                    "confidence": 70,
                    "component": None,
                    "component_type": None
                }

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
                    "confidence": 80,
                    "component": None,
                    "component_type": None
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
                "confidence": 50,
                "component": None,
                "component_type": None
            }

    return {
        "matched": False,
        "software_name": None,
        "device_version": None,
        "normalized_id": None,
        "match_type": "none",
        "confidence": 0,
        "component": None,
        "component_type": None
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
