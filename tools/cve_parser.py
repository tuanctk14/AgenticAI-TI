"""
tools/cve_parser.py - Parse CVE description to extract affected software, versions, and OS
"""
import re
from packaging import version as pkg_version

def parse_cve_metadata(cve_dict: dict) -> dict:
    """
    Parse CVE description to extract:
    - affected_app: Application name (e.g., "WordPress", "Apache Log4j", "OpenCATS")
    - affected_versions: Version range (e.g., "1.48 and earlier", "2.0-beta9 through 2.15.0")
    - max_version: Latest vulnerable version (e.g., "1.48", "2.15.0")
    - min_version: Earliest vulnerable version if range specified
    - affected_os: OS/Platform (e.g., "Windows", "Linux", "All")
    - keywords: List of keywords to match in CMDB

    Returns dict with parsed metadata for matching
    """
    cve_id = cve_dict.get("id", "").upper()
    description = cve_dict.get("description", "").strip()

    result = {
        "cve_id": cve_id,
        "affected_app": None,
        "affected_versions": None,
        "max_version": None,
        "min_version": None,
        "affected_os": None,
        "keywords": [],
        "raw_description": description[:200]  # First 200 chars
    }

    if not description:
        return result

    desc_lower = description.lower()

    # ── Pattern 1: "App version X and earlier" / "App X through Y" ────
    patterns = [
        # "App X through Y" - NO version keyword needed (FIRST - to match "2.0-beta9 through 2.15.0")
        r'([a-z\s\d\.\-]+?)\s+([0-9][0-9\.\-\w]*)\s+(?:through|to)\s+([0-9][0-9\.\-\w]*)',
        # "App version X and earlier" - WITH version keyword
        r'([a-z\s\d\.\-]+?)\s+(?:version|versions?)\s+([0-9][0-9\.\-\w]*)\s+and\s+earlier',
        # "App X.Y and earlier" - NO version keyword
        r'([a-z\s\d\.\-]+?)\s+([0-9][0-9\.\-\w]*)\s+and\s+earlier',
        # "App X.Y contains"
        r'([a-z\s\d\.\-]+?)\s+([0-9][0-9\.\-\w]*)\s+contains',
    ]

    for pattern in patterns:
        match = re.search(pattern, desc_lower)
        if match:
            if len(match.groups()) >= 2:
                result["affected_app"] = match.group(1).strip().title()

                if len(match.groups()) >= 3:
                    # Range case: X through Y (groups: app, min_version, max_version)
                    result["min_version"] = match.group(2).strip()
                    result["max_version"] = match.group(3).strip()
                else:
                    # Single version case: X and earlier (groups: app, version)
                    result["max_version"] = match.group(2).strip()

                result["affected_versions"] = description[match.start():match.end()]
                break

    # ── Fallback: Extract first version number mentioned ────
    if not result["affected_app"]:
        # Look for common app names first
        app_patterns = {
            "WordPress Plugin Download From Files": r'wordpress.*?download\s+from\s+files',
            "WordPress": r'wordpress',
            "Apache Log4j": r'apache\s+log4j|log4j2?',
            "Apache HTTP Server": r'apache\s+(?:http\s+)?server|httpd',
            "OpenSSL": r'openssl',
            "MySQL": r'mysql',
            "OpenCATS": r'opencats',
            "Spring Framework": r'spring\s+(?:framework|boot)',
            "Tomcat": r'tomcat',
            "Cisco": r'cisco',
        }

        for app_name, app_regex in app_patterns.items():
            if re.search(app_regex, desc_lower):
                result["affected_app"] = app_name
                result["keywords"].append(app_name.lower())
                break

    # ── Extract version numbers ────
    if not result["max_version"]:
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', description)
        if version_match:
            result["max_version"] = version_match.group(1)

    # ── Detect OS/Platform ────
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

    # ── Build keywords for matching ────
    if result["affected_app"]:
        # Add keywords: split app name and add each part
        keywords = result["affected_app"].lower().split()
        result["keywords"].extend(keywords)

    # Add common keywords found in description
    common_keywords = ["wordpress", "apache", "log4j", "openssl", "mysql", "php",
                       "tomcat", "spring", "cisco", "adobe", "chrome", "openssh"]
    for kw in common_keywords:
        if kw in desc_lower:
            if kw not in result["keywords"]:
                result["keywords"].append(kw)

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


def match_app_in_device(app_keywords: list, device_software: list) -> dict:
    """
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
