"""
tools/analyzer.py - Device-level analysis to avoid duplication
"""
import json
from typing import Dict, List, Optional


def aggregate_cves_by_device(matched_devices: List[dict], collected_cves: List[dict]) -> Dict:
    """
    Group CVEs by device to identify unique CVEs per device.

    Returns: {device_id: {"device_info": {...}, "cve_ids": [...], "unique_cve_count": N}}
    """
    print(f"  [Analyzer] Aggregating {len(matched_devices)} device matches...")

    device_map = {}

    for match in matched_devices:
        device_id = match.get("device_id")
        cve_id = match.get("cve_id")

        if device_id not in device_map:
            device_map[device_id] = {
                "device_info": {
                    "device_id": device_id,
                    "hostname": match.get("hostname"),
                    "ip": match.get("ip"),
                    "department": match.get("department"),
                    "criticality": match.get("criticality"),
                    "os": match.get("os"),
                    "location": match.get("location"),
                },
                "cve_ids": set(),
                "risk_levels": {},
            }

        device_map[device_id]["cve_ids"].add(cve_id)
        device_map[device_id]["risk_levels"][cve_id] = match.get("risk_level")

    # Convert sets to lists for JSON serialization
    result = {}
    for device_id, data in device_map.items():
        result[device_id] = {
            "device_info": data["device_info"],
            "cve_ids": sorted(list(data["cve_ids"])),
            "risk_levels": data["risk_levels"],
            "unique_cve_count": len(data["cve_ids"]),
        }

    print(f"  [Analyzer]  Grouped into {len(result)} unique devices")
    return {
        "context": result,
        "source": "Analyzer",
        "total_devices": len(result),
    }


def get_unique_cves_per_device(device_cve_map: Dict) -> Dict[str, List[str]]:
    """
    Extract unique CVEs per device for streamlined analysis.

    Returns: {device_id: [cve_id, ...]}
    """
    result = {}
    for device_id, data in device_cve_map.items():
        result[device_id] = data.get("cve_ids", [])
    return result


def get_critical_devices(device_cve_map: Dict) -> List[str]:
    """
    Identify critical devices (with CRITICAL or HIGH risk CVEs).
    """
    critical_devices = []
    for device_id, data in device_cve_map.items():
        risk_levels = data.get("risk_levels", {})
        if any(level in ("CRITICAL", "HIGH") for level in risk_levels.values()):
            critical_devices.append(device_id)
    return critical_devices


def summarize_device_risks(device_cve_map: Dict) -> Dict:
    """
    Create summary of device risks for quick assessment.
    """
    summary = {
        "total_devices": len(device_cve_map),
        "critical_devices": 0,
        "high_devices": 0,
        "medium_devices": 0,
        "device_risk_distribution": {},
    }

    for device_id, data in device_cve_map.items():
        risk_levels = data.get("risk_levels", {})
        max_risk = "LOW"

        if any(level == "CRITICAL" for level in risk_levels.values()):
            max_risk = "CRITICAL"
            summary["critical_devices"] += 1
        elif any(level == "HIGH" for level in risk_levels.values()):
            max_risk = "HIGH"
            summary["high_devices"] += 1
        elif any(level == "MEDIUM" for level in risk_levels.values()):
            max_risk = "MEDIUM"
            summary["medium_devices"] += 1

        summary["device_risk_distribution"][device_id] = {
            "hostname": data["device_info"]["hostname"],
            "risk_level": max_risk,
            "cve_count": data["unique_cve_count"],
        }

    return summary
