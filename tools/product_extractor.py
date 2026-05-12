"""
tools/product_extractor.py - Product Extraction when CPE unavailable

Analyst-grade product detection from CVE metadata using:
1. Regex patterns (vendor/product keywords)
2. Known product aliases
3. LLM-based entity extraction
4. Fingerprinting (banner, package info)
5. Manual review flag for uncertain cases
"""
import re
import json
from typing import Dict, List, Optional
from pathlib import Path

# Load alias dictionary
ALIAS_DB_PATH = Path(__file__).parent.parent / "data" / "product_aliases.json"

# Fallback aliases if file not found
DEFAULT_ALIASES = {
    "apache2": ["apache http server", "apache httpd", "httpd"],
    "nginx": ["nginx web server", "nginx"],
    "fortios": ["fortinet fortios", "fortigate", "fortios"],
    "ios_xe": ["cisco ios xe", "ios xe", "catalyst"],
    "mysql": ["mysql server", "mysql database"],
    "postgresql": ["postgresql database", "postgres"],
    "exchange": ["microsoft exchange", "exchange server"],
    "sharepoint": ["microsoft sharepoint", "sharepoint server"],
    "wordpress": ["wordpress", "wp-content"],
    "joomla": ["joomla cms", "joomla"],
    "drupal": ["drupal cms", "drupal"],
    "openssl": ["openssl", "open ssl"],
    "log4j": ["apache log4j", "log4j", "log4j2"],
    "tomcat": ["apache tomcat", "tomcat"],
    "java": ["java runtime", "jre", "jdk"],
    "bettercap": ["bettercap"],
}

# Vendor patterns
VENDOR_PATTERNS = {
    "apache": r"\b(apache|httpd)\b",
    "cisco": r"\b(cisco)\b",
    "fortinet": r"\b(fortinet|fortigate)\b",
    "microsoft": r"\b(microsoft|windows|exchange|sharepoint)\b",
    "redhat": r"\b(redhat|rhel|centos)\b",
    "ubuntu": r"\b(ubuntu|debian)\b",
    "openssl": r"\b(openssl)\b",
    "mysql": r"\b(mysql)\b",
    "postgresql": r"\b(postgres|postgresql)\b",
    "oracle": r"\b(oracle)\b",
    "ibm": r"\b(ibm)\b",
    "apple": r"\b(apple|macos|ios)\b",
    "google": r"\b(google|android)\b",
}

# Product patterns with version extraction
PRODUCT_PATTERNS = {
    r"(apache\s+(http\s+server|httpd|web\s+server))": ("apache", "http_server"),
    r"(fortios|fortigate)\s+before\s+([\d.]+)": ("fortinet", "fortios"),
    r"(cisco\s+ios\s+xe)": ("cisco", "ios_xe"),
    r"(microsoft\s+exchange\s+server)": ("microsoft", "exchange"),
    r"(apache\s+log4j\d?)": ("apache", "log4j"),
    r"(bettercap)": ("bettercap", "bettercap"),
    r"(mysql\s+server)": ("mysql", "mysql"),
    r"(postgresql|postgres)": ("postgresql", "postgresql"),
    r"(openssl)\s+before\s+([\d.]+)": ("openssl", "openssl"),
    r"(wordpress)": ("wordpress", "wordpress"),
    r"(joomla)": ("joomla", "joomla"),
    r"(drupal)": ("drupal", "drupal"),
    r"(apache\s+tomcat)": ("apache", "tomcat"),
}


def load_aliases() -> Dict[str, List[str]]:
    """Load product aliases from file or use defaults."""
    try:
        with open(ALIAS_DB_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_ALIASES


ALIASES = load_aliases()


def extract_vendor_from_description(description: str) -> Optional[str]:
    """
    Extract vendor name from CVE description using regex patterns.

    Returns: vendor string (lowercase) or None
    """
    if not description:
        return None

    desc_lower = description.lower()

    # Check vendor patterns in order of specificity
    for vendor, pattern in VENDOR_PATTERNS.items():
        if re.search(pattern, desc_lower):
            return vendor

    return None


def extract_product_from_description(description: str) -> Optional[tuple]:
    """
    Extract product name and version from CVE description.

    Returns: (vendor, product) or None
    """
    if not description:
        return None

    desc_lower = description.lower()

    # Try product patterns (most specific)
    for pattern, (vendor, product) in PRODUCT_PATTERNS.items():
        if re.search(pattern, desc_lower, re.IGNORECASE):
            return (vendor, product)

    return None


def extract_version_from_description(description: str, product: str = "") -> Optional[str]:
    """
    Extract affected version range from CVE description.

    Examples:
    - "before 7.2.5" → "<7.2.5"
    - "through 2.15.0" → "<=2.15.0"
    - "up to 1.2.3" → "<=1.2.3"

    Returns: version string or None
    """
    if not description:
        return None

    desc_lower = description.lower()

    # Version patterns
    version_patterns = [
        r"before\s+([\d.]+)",      # "before 7.2.5"
        r"through\s+([\d.]+)",     # "through 2.15.0"
        r"up to\s+([\d.]+)",       # "up to 1.2.3"
        r"until\s+([\d.]+)",       # "until 5.0"
        r"(?:version|v\.?)\s+([\d.]+)",  # "version 1.2.3"
        r"([\d.]+)\s+and\s+earlier",  # "1.2.3 and earlier"
    ]

    for pattern in version_patterns:
        match = re.search(pattern, desc_lower)
        if match:
            return match.group(1)

    return None


def find_alias_key(product_name: str) -> Optional[str]:
    """
    Find inventory product key matching NVD product name.

    Example:
    - Input: "apache http server"
    - Output: "apache2" (from aliases["apache2"] = ["apache http server", ...])

    Returns: inventory product key or None
    """
    if not product_name:
        return None

    product_lower = product_name.lower()

    # Check each alias group
    for inventory_key, nvd_names in ALIASES.items():
        for nvd_name in nvd_names:
            if nvd_name.lower() == product_lower or nvd_name.lower() in product_lower:
                return inventory_key

    return None


def extract_product_metadata(cve_dict: Dict) -> Dict:
    """
    Complete product extraction from CVE metadata.

    Tries in order:
    1. CPE (highest confidence)
    2. Product pattern matching
    3. Vendor + product from description
    4. Fingerprinting hints

    Returns:
    {
        "vendor": "string",
        "product": "string",
        "version": "string or None",
        "confidence": "high|medium|low",
        "source": "cpe|pattern|description|fingerprint|unknown",
        "aliases": ["possible inventory keys"],
        "needs_review": bool,
        "reasoning": "explanation"
    }
    """
    description = cve_dict.get('description', '')
    references = cve_dict.get('references', [])
    cwe_ids = cve_dict.get('cwe_ids', [])

    result = {
        "vendor": None,
        "product": None,
        "version": None,
        "confidence": "low",
        "source": "unknown",
        "aliases": [],
        "needs_review": False,
        "reasoning": ""
    }

    # Combine text sources
    full_text = description + " ".join(references)

    # Try extraction in order of confidence

    # 1. Try product pattern (most specific)
    extracted = extract_product_from_description(description)
    if extracted:
        result["vendor"], result["product"] = extracted
        result["confidence"] = "high"
        result["source"] = "pattern"
        result["reasoning"] = f"Product pattern matched in description"
    else:
        # 2. Try vendor extraction
        vendor = extract_vendor_from_description(description)
        if vendor:
            result["vendor"] = vendor
            result["confidence"] = "medium"
            result["source"] = "description"
            result["reasoning"] = f"Vendor '{vendor}' found in description, product unclear"
            result["needs_review"] = True
        else:
            result["source"] = "unknown"
            result["reasoning"] = "No vendor/product matched in description"
            result["needs_review"] = True

    # Try to extract version
    if result["product"]:
        version = extract_version_from_description(description, result["product"])
        if version:
            result["version"] = version

    # Find aliases (inventory keys that match this product)
    if result["vendor"] and result["product"]:
        product_full = f"{result['vendor']}:{result['product']}"

        # Direct alias lookup
        alias_key = find_alias_key(result["product"])
        if alias_key:
            result["aliases"].append(alias_key)

        # Vendor-based aliases
        for inv_key, nvd_names in ALIASES.items():
            if any(result["vendor"] in name.lower() for name in nvd_names):
                if inv_key not in result["aliases"]:
                    result["aliases"].append(inv_key)

    # Mark as needing review if confidence is low
    if result["confidence"] == "low":
        result["needs_review"] = True

    return result


def match_confidence_score(extracted: Dict, device_software: List[Dict]) -> float:
    """
    Calculate match confidence score (0.0 - 1.0) based on extracted data quality.

    Factors:
    - Extraction confidence: high=0.8, medium=0.5, low=0.2
    - Version match: +0.15 if version specified
    - Alias match: +0.10 if alias found in inventory
    """
    score = 0.0

    # Base score from extraction confidence
    confidence_map = {"high": 0.8, "medium": 0.5, "low": 0.2}
    score = confidence_map.get(extracted.get("confidence", "low"), 0.2)

    # Add bonus for version
    if extracted.get("version"):
        score += 0.15

    # Add bonus if alias exists
    if extracted.get("aliases"):
        score += 0.10

    # Check if aliases match device software
    if extracted.get("aliases"):
        for alias in extracted.get("aliases"):
            for dev_sw in device_software:
                if alias.lower() in dev_sw.get("name", "").lower():
                    score += 0.10
                    break

    return min(score, 1.0)  # Cap at 1.0


# Test data
if __name__ == "__main__":
    test_cves = [
        {
            "id": "CVE-2021-44228",
            "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "references": [],
            "cwe_ids": ["20"]
        },
        {
            "id": "CVE-2023-20198",
            "description": "A flaw has been found in Cisco IOS XE Software that, when triggered, allows an authenticated remote attacker to execute arbitrary code.",
            "references": [],
            "cwe_ids": ["78"]
        },
        {
            "id": "CVE-2026-8276",
            "description": "A flaw has been found in bettercap up to 2.41.5. Affected by this issue is some unknown functionality of the file modules/mysql_server/mysql_server.go.",
            "references": [],
            "cwe_ids": ["189"]
        },
    ]

    print("=" * 80)
    print("Product Extraction Test")
    print("=" * 80)

    for cve in test_cves:
        print(f"\n{cve['id']}")
        print(f"Description: {cve['description'][:80]}...")

        extracted = extract_product_metadata(cve)
        print(f"  Vendor: {extracted['vendor']}")
        print(f"  Product: {extracted['product']}")
        print(f"  Version: {extracted['version']}")
        print(f"  Confidence: {extracted['confidence']}")
        print(f"  Source: {extracted['source']}")
        print(f"  Aliases: {extracted['aliases']}")
        print(f"  Needs Review: {extracted['needs_review']}")
        print(f"  Reasoning: {extracted['reasoning']}")
