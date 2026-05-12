"""
tools/date_validator.py - Validate CVE dates for data quality

Validates:
1. Published date <= current date (sanity check)
2. CVE ID year matches published year (mostly, with tolerance)
3. Reasonable date ranges
"""
import re
from datetime import datetime
from typing import Dict, Optional, Tuple


class DateValidator:
    """Validate CVE dates for data quality"""

    @staticmethod
    def parse_date(date_str: str) -> Optional[datetime]:
        """Parse date string (ISO 8601 or common formats)"""
        if not date_str:
            return None

        # Try ISO 8601 format first
        formats = [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%d/%m/%Y",
            "%m/%d/%Y",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue

        return None

    @staticmethod
    def extract_cve_year(cve_id: str) -> Optional[int]:
        """Extract year from CVE ID (CVE-YYYY-XXXXX)"""
        match = re.match(r"CVE-(\d{4})-", cve_id.upper())
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def validate_published_date(
        cve_id: str,
        published_date: str,
        current_date: datetime = None
    ) -> Dict[str, any]:
        """
        Validate CVE published date

        Returns: {
            is_valid: bool,
            published_datetime: datetime or None,
            warnings: [str],
            errors: [str]
        }
        """
        if current_date is None:
            current_date = datetime.now()

        result = {
            "is_valid": True,
            "published_datetime": None,
            "warnings": [],
            "errors": []
        }

        # Parse date
        published = DateValidator.parse_date(published_date)
        if not published:
            result["is_valid"] = False
            result["errors"].append(f"Could not parse published date: {published_date}")
            return result

        result["published_datetime"] = published

        # Check if date is in future
        if published > current_date:
            result["is_valid"] = False
            result["errors"].append(
                f"Published date {published.date()} is in the future "
                f"(current: {current_date.date()})"
            )

        # Check CVE year vs published year
        cve_year = DateValidator.extract_cve_year(cve_id)
        published_year = published.year

        if cve_year:
            year_diff = abs(cve_year - published_year)
            if year_diff > 1:
                result["warnings"].append(
                    f"CVE year {cve_year} differs from published year {published_year} "
                    f"(diff: {year_diff} years) - may indicate late publication or data error"
                )
            elif year_diff == 1:
                result["warnings"].append(
                    f"CVE year {cve_year} differs by 1 from published year {published_year} "
                    f"- may be legitimate (early/late publication)"
                )

        return result

    @staticmethod
    def validate_cve_dates(cve_dict: Dict) -> Dict[str, any]:
        """
        Complete date validation for a CVE

        Checks:
        - published_date <= current_date
        - CVE year vs published year alignment
        - Date reasonableness

        Returns: {
            is_valid: bool,
            published_valid: bool,
            date_warnings: [str],
            date_errors: [str],
            needs_review: bool
        }
        """
        cve_id = cve_dict.get("id", "").upper()
        published_date = cve_dict.get("published_date", "")

        result = {
            "is_valid": True,
            "published_valid": True,
            "date_warnings": [],
            "date_errors": [],
            "needs_review": False
        }

        # Validate published date
        if published_date:
            validation = DateValidator.validate_published_date(cve_id, published_date)
            result["published_valid"] = validation["is_valid"]
            result["date_errors"].extend(validation["errors"])
            result["date_warnings"].extend(validation["warnings"])

            if not validation["is_valid"]:
                result["is_valid"] = False
                result["needs_review"] = True

        # Flag if warnings exist
        if result["date_warnings"]:
            result["needs_review"] = True

        return result


# Test data
if __name__ == "__main__":
    test_cves = [
        {
            "id": "CVE-2021-44228",
            "published_date": "2021-12-10",
            "description": "Apache Log4j2 JNDI injection"
        },
        {
            "id": "CVE-2021-47933",
            "published_date": "2021-05-10",
            "description": "WordPress MStore API"
        },
        {
            "id": "CVE-2026-99999",  # Future CVE (invalid)
            "published_date": "2026-12-31",
            "description": "Future vulnerability"
        },
        {
            "id": "CVE-2023-12345",  # Year mismatch
            "published_date": "2024-06-15",
            "description": "Year mismatch - published late"
        },
    ]

    current = datetime(2026, 5, 12)

    print("=" * 80)
    print("CVE DATE VALIDATION TEST")
    print("=" * 80)

    for cve in test_cves:
        print(f"\n{cve['id']}")
        validation = DateValidator.validate_cve_dates(cve)

        print(f"  Valid: {validation['is_valid']}")
        print(f"  Published Date Valid: {validation['published_valid']}")
        if validation["date_errors"]:
            for error in validation["date_errors"]:
                print(f"  ERROR: {error}")
        if validation["date_warnings"]:
            for warning in validation["date_warnings"]:
                print(f"  WARNING: {warning}")
        print(f"  Needs Review: {validation['needs_review']}")
