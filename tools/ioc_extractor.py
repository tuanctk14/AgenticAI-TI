# -*- coding: utf-8 -*-
"""
tools/ioc_extractor.py - Trích xuất IOC từ thông tin malware/campaign

Hệ thống trích xuất các chỉ số đe dọa (IOC) từ:
- Mô tả malware/campaign
- Cơ sở dữ liệu mở (OpenCTI)
- Thông tin liên quan đến CVE

Hỗ trợ các loại IOC:
- IP addresses (IPv4, IPv6)
- Domains
- Hashes (MD5, SHA-1, SHA-256)
- URLs
- Email addresses
- File names
"""

import re
from typing import Set, List, Dict


class IOCExtractor:
    """Trích xuất IOC từ các nguồn tài liệu."""

    # Regex patterns cho các loại IOC
    PATTERNS = {
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "ipv6": r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "domain": r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}",
        "url": r"https?://(?:www\.)?(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=])+",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    }

    @staticmethod
    def extract_from_text(text: str, ioc_types: List[str] = None) -> Dict[str, Set[str]]:
        """
        Trích xuất IOC từ text.

        Args:
            text: Đoạn text cần phân tích
            ioc_types: Danh sách loại IOC cần trích (None = tất cả)

        Returns: {
            "ipv4": set(...),
            "ipv6": set(...),
            "md5": set(...),
            "sha1": set(...),
            "sha256": set(...),
            "domain": set(...),
            "url": set(...),
            "email": set(...),
        }
        """
        if not text:
            return {ioc_type: set() for ioc_type in IOCExtractor.PATTERNS.keys()}

        results = {}
        types_to_check = ioc_types or list(IOCExtractor.PATTERNS.keys())

        for ioc_type in types_to_check:
            if ioc_type in IOCExtractor.PATTERNS:
                pattern = IOCExtractor.PATTERNS[ioc_type]
                matches = re.findall(pattern, text, re.IGNORECASE)
                results[ioc_type] = set(matches)
            else:
                results[ioc_type] = set()

        return results

    @staticmethod
    def extract_from_malware(malware: dict) -> Dict[str, any]:
        """
        Trích xuất IOC từ object malware.

        Args:
            malware: Dict chứa thông tin malware

        Returns: {
            "iocs": {
                "ipv4": [...],
                "domain": [...],
                ...
            },
            "source": "malware",
            "malware_name": "...",
            "confidence": 90,
        }
        """
        malware_name = malware.get("name", "Unknown")
        description = malware.get("description", "")
        aliases = " ".join(malware.get("aliases", []))

        # Kết hợp tất cả text
        combined_text = f"{malware_name} {description} {aliases}"

        # Trích xuất IOC
        extracted_iocs = IOCExtractor.extract_from_text(combined_text)

        # Chỉ giữ những loại có dữ liệu
        iocs = {k: list(v) for k, v in extracted_iocs.items() if v}

        return {
            "iocs": iocs,
            "source": "malware",
            "malware_name": malware_name,
            "confidence": malware.get("confidence", 75),
            "total_iocs": sum(len(v) for v in iocs.values()),
        }

    @staticmethod
    def extract_from_campaign(campaign: dict) -> Dict[str, any]:
        """
        Trích xuất IOC từ object campaign.

        Args:
            campaign: Dict chứa thông tin campaign

        Returns: {
            "iocs": {...},
            "source": "campaign",
            "campaign_name": "...",
            "confidence": 85,
        }
        """
        campaign_name = campaign.get("name", "Unknown")
        description = campaign.get("description", "")

        # Kết hợp text
        combined_text = f"{campaign_name} {description}"

        # Trích xuất IOC
        extracted_iocs = IOCExtractor.extract_from_text(combined_text)

        # Chỉ giữ những loại có dữ liệu
        iocs = {k: list(v) for k, v in extracted_iocs.items() if v}

        return {
            "iocs": iocs,
            "source": "campaign",
            "campaign_name": campaign_name,
            "confidence": campaign.get("confidence", 80),
            "total_iocs": sum(len(v) for v in iocs.values()),
        }

    @staticmethod
    def extract_from_cve_relationships(cve_dict: dict) -> Dict[str, List[dict]]:
        """
        Trích xuất tất cả IOC từ các mối liên hệ CVE.

        Args:
            cve_dict: CVE dict với relationships

        Returns: {
            "cve_id": "CVE-2021-44228",
            "iocs_extracted": [
                {"type": "domain", "value": "...", "source": "malware", "malware": "Conti"},
                ...
            ],
            "summary": {
                "ipv4": 5,
                "domain": 12,
                "sha256": 3,
                ...
            }
        }
        """
        cve_id = cve_dict.get("id", "Unknown")
        relationships = cve_dict.get("relationships", {})

        all_iocs = []
        ioc_counts = {ioc_type: 0 for ioc_type in IOCExtractor.PATTERNS.keys()}

        # Từ malware
        for malware in relationships.get("malwares", []):
            result = IOCExtractor.extract_from_malware(malware)
            for ioc_type, ioc_list in result["iocs"].items():
                for ioc_value in ioc_list:
                    all_iocs.append({
                        "type": ioc_type,
                        "value": ioc_value,
                        "source": "malware",
                        "malware_name": malware.get("name", ""),
                        "confidence": result.get("confidence", 75),
                    })
                    ioc_counts[ioc_type] += len(ioc_list)

        # Từ campaign
        for campaign in relationships.get("campaigns", []):
            result = IOCExtractor.extract_from_campaign(campaign)
            for ioc_type, ioc_list in result["iocs"].items():
                for ioc_value in ioc_list:
                    all_iocs.append({
                        "type": ioc_type,
                        "value": ioc_value,
                        "source": "campaign",
                        "campaign_name": campaign.get("name", ""),
                        "confidence": result.get("confidence", 80),
                    })
                    ioc_counts[ioc_type] += len(ioc_list)

        # Deduplication by value
        unique_iocs = {}
        for ioc in all_iocs:
            key = (ioc["type"], ioc["value"])
            if key not in unique_iocs:
                unique_iocs[key] = ioc
            else:
                # Giữ confidence cao nhất
                if ioc.get("confidence", 0) > unique_iocs[key].get("confidence", 0):
                    unique_iocs[key] = ioc

        return {
            "cve_id": cve_id,
            "iocs_extracted": list(unique_iocs.values()),
            "summary": {k: ioc_counts[k] for k in ioc_counts if ioc_counts[k] > 0},
            "total_unique_iocs": len(unique_iocs),
            "status": "extracted" if unique_iocs else "no_iocs"
        }


def extract_iocs_from_enrichment(cve_dict: dict) -> dict:
    """
    Hàm tiêu chuẩn để trích xuất IOC từ CVE enriched.

    Args:
        cve_dict: CVE object với relationships từ enrichment

    Returns: Extraction result
    """
    print(f"  [IOCExtractor] Trích xuất IOC từ {cve_dict.get('id', 'Unknown')}...")

    try:
        result = IOCExtractor.extract_from_cve_relationships(cve_dict)

        if result["status"] == "extracted":
            print(f"  [IOCExtractor] SUCCESS: {result['total_unique_iocs']} IOCs trích xuất")
            if result["summary"]:
                summary_str = ", ".join(f"{k}:{v}" for k, v in result["summary"].items())
                print(f"    Loại: {summary_str}")
        else:
            print(f"  [IOCExtractor] Không tìm thấy IOC")

        return result

    except Exception as e:
        print(f"  [IOCExtractor] ERROR: {e}")
        return {
            "cve_id": cve_dict.get("id"),
            "status": "error",
            "error": str(e)
        }
