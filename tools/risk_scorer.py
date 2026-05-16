"""
tools/risk_scorer.py - Analyst-Grade Risk-Based Vulnerability Scoring

Cách tính chuẩn cho nhiều CVE trên cùng thiết bị:

Device Risk Score =
(
  Max CVSS × 0.35
  + Avg CVSS × 0.15
  + EPSS × 0.15
  + KEV × 0.10
  + Exploit × 0.10
  + Asset Criticality × 0.10
  + Exposure × 0.05
) × 100

Classification:
- 0-19: Low
- 20-39: Medium
- 40-59: High
- 60-79: Critical
- 80-100: Emergency
"""

from typing import Dict, List, Tuple


class RiskScorer:
    """Tính Risk Score cho thiết bị dựa trên nhiều yếu tố"""

    # CVSS to severity mapping
    CVSS_TO_SEVERITY = {
        (9.0, 10.0): "CRITICAL",
        (7.0, 8.9): "HIGH",
        (4.0, 6.9): "MEDIUM",
        (0.1, 3.9): "LOW",
        (0.0, 0.0): "NONE",
    }

    @staticmethod
    def cvss_to_severity(cvss: float) -> str:
        """Convert CVSS score to severity level"""
        for (min_score, max_score), severity in RiskScorer.CVSS_TO_SEVERITY.items():
            if min_score <= cvss <= max_score:
                return severity
        return "UNKNOWN"

    @staticmethod
    def parse_cvss(cvss_value) -> float:
        """Parse CVSS value safely"""
        try:
            if isinstance(cvss_value, (int, float)):
                return float(cvss_value)
            if isinstance(cvss_value, str) and cvss_value != "N/A":
                return float(cvss_value.split()[0])  # Handle "9.8 (CVSS 3.1)"
            return 0.0
        except (ValueError, TypeError, AttributeError):
            return 0.0

    @staticmethod
    def calculate_device_risk_score(
        cves: List[Dict],
        device_criticality: str = "MEDIUM",
        internet_exposed: bool = False,
        is_dc: bool = False,
        is_production: bool = True,
    ) -> Tuple[float, str]:
        """
        Tính Risk Score cho một thiết bị dựa trên các CVE của nó.

        Công thức (Enhanced với enrichment data):
        Risk Score = (
          Max CVSS × 0.25
          + Avg CVSS × 0.10
          + EPSS × 0.15        [NEW - nếu có enrichment]
          + KEV Bonus × 0.10   [NEW - nếu có enrichment]
          + Exploit Bonus × 0.10 [NEW - nếu có enrichment]
          + Asset Criticality × 0.15
          + Exposure × 0.10
        ) × 100

        Ghi chú: Nếu enrichment data không có, fallback to CVSS-only scoring

        Args:
            cves: Danh sách CVE dính vào thiết bị
            device_criticality: LOW, MEDIUM, HIGH, CRITICAL (mức độ quan trọng của thiết bị)
            internet_exposed: Thiết bị expose ra internet?
            is_dc: Là Domain Controller?
            is_production: Là production server?

        Returns:
            (risk_score, risk_level) - Tuple của điểm số (0-100) và mức độ
        """
        if not cves:
            return (0.0, "LOW")

        # Layer 1: Extract CVSS scores + enrichment data
        cvss_scores = []
        epss_scores = []
        kev_count = 0
        exploit_count = 0

        for cve in cves:
            cvss = RiskScorer.parse_cvss(cve.get("cvss_score", 0))
            if cvss > 0:
                cvss_scores.append(cvss)

            # Extract enrichment data if available
            enrichment = cve.get("enrichment", {})
            if enrichment:
                # EPSS
                epss = enrichment.get("epss_score")
                if epss:
                    try:
                        epss_val = float(epss)
                        epss_scores.append(epss_val)
                    except (ValueError, TypeError):
                        pass

                # KEV bonus
                if enrichment.get("kev_listed"):
                    kev_count += 1

                # Exploit indicators
                if enrichment.get("public_exploit") or enrichment.get("metasploit"):
                    exploit_count += 1
                if enrichment.get("ransomware_activity"):
                    exploit_count += 2  # Double weight for ransomware

        if not cvss_scores:
            return (0.0, "LOW")

        max_cvss = max(cvss_scores)
        avg_cvss = sum(cvss_scores) / len(cvss_scores)

        # Layer 2: Asset Criticality bonus (0-1 scale)
        asset_criticality_bonus = 0.0
        if device_criticality == "CRITICAL":
            asset_criticality_bonus = 1.0
        elif device_criticality == "HIGH":
            asset_criticality_bonus = 0.8
        elif device_criticality == "MEDIUM":
            asset_criticality_bonus = 0.5
        elif device_criticality == "LOW":
            asset_criticality_bonus = 0.2

        # Add DC/Production bonus
        if is_dc:
            asset_criticality_bonus = min(1.0, asset_criticality_bonus + 0.3)
        if is_production:
            asset_criticality_bonus = min(1.0, asset_criticality_bonus + 0.2)

        # Layer 3: Exposure factor (0-1 scale)
        exposure_bonus = 1.0 if internet_exposed else 0.5

        # Layer 4: Enrichment bonuses (only if available)
        epss_bonus = 0.0
        kev_bonus = 0.0
        exploit_bonus = 0.0

        if epss_scores:
            avg_epss = sum(epss_scores) / len(epss_scores)
            epss_bonus = avg_epss * 0.15  # 0-15% weight

        if kev_count > 0:
            # Scale KEV bonus based on percentage of CVEs that are KEV-listed
            kev_percentage = min(1.0, kev_count / len(cves))
            kev_bonus = kev_percentage * 0.10  # 0-10% weight

        if exploit_count > 0:
            # Scale exploit bonus based on exploit indicators
            exploit_percentage = min(1.0, exploit_count / (len(cves) * 2))
            exploit_bonus = exploit_percentage * 0.10  # 0-10% weight

        # Calculate final risk score using weighted formula
        risk_score = (
            (max_cvss / 10.0) * 0.25  # Max CVSS
            + (avg_cvss / 10.0) * 0.10  # Avg CVSS
            + epss_bonus  # EPSS (0-15%)
            + kev_bonus  # KEV bonus (0-10%)
            + exploit_bonus  # Exploit bonus (0-10%)
            + asset_criticality_bonus * 0.15  # Asset Criticality
            + exposure_bonus * 0.10  # Exposure
        ) * 100

        # Classify risk level
        risk_level = RiskScorer.classify_risk(risk_score)

        return (min(100.0, risk_score), risk_level)

    @staticmethod
    def classify_risk(risk_score: float) -> str:
        """Classify risk score to level"""
        if risk_score >= 80:
            return "EMERGENCY"
        elif risk_score >= 60:
            return "CRITICAL"
        elif risk_score >= 40:
            return "HIGH"
        elif risk_score >= 20:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def get_remediation_timeline(risk_level: str) -> str:
        """Get remediation timeline based on risk level"""
        timelines = {
            "EMERGENCY": "Xử lý NGAY (1 giờ)",
            "CRITICAL": "Xử lý ngay trong 24 giờ",
            "HIGH": "Xử lý trong 72 giờ",
            "MEDIUM": "Lên lịch xử lý trong 2 tuần",
            "LOW": "Theo lịch bảo trì định kỳ",
        }
        return timelines.get(risk_level, "Cần đánh giá")

    @staticmethod
    def get_risk_color(risk_level: str) -> str:
        """Get HTML color for risk level"""
        colors = {
            "EMERGENCY": "#ff0000",  # Bright red
            "CRITICAL": "#ff4444",  # Red
            "HIGH": "#ff8800",  # Orange
            "MEDIUM": "#ffcc00",  # Yellow
            "LOW": "#00cc00",  # Green
        }
        return colors.get(risk_level, "#ffffff")

    @staticmethod
    def calculate_and_explain(
        cves: List[Dict],
        device_criticality: str = "MEDIUM",
        internet_exposed: bool = False,
        is_dc: bool = False,
        is_production: bool = True,
    ) -> Dict:
        """
        Tính Risk Score và trả về chi tiết tính toán.

        Returns:
            {
                "risk_score": float,
                "risk_level": str,
                "factors": {
                    "max_cvss": float,
                    "avg_cvss": float,
                    "epss_score": float,
                    "kev_bonus": float,
                    "exploit_bonus": float,
                    "asset_criticality": float,
                    "exposure_bonus": float,
                },
                "breakdown": str (chi tiết tính toán)
            }
        """
        if not cves:
            return {
                "risk_score": 0.0,
                "risk_level": "LOW",
                "factors": {},
                "breakdown": "Không có CVE"
            }

        # Layer 1: Extract CVSS scores
        cvss_scores = []
        actively_exploited_count = 0

        for cve in cves:
            cvss = RiskScorer.parse_cvss(cve.get("cvss_score", 0))
            if cvss > 0:
                cvss_scores.append(cvss)

            # Check if actively exploited
            exploit_status = str(cve.get("exploit_status", "")).upper()
            if exploit_status in ("ACTIVELY_EXPLOITED", "POC_AVAILABLE", "EXPLOITED_IN_THE_WILD"):
                actively_exploited_count += 1

        if not cvss_scores:
            return {
                "risk_score": 0.0,
                "risk_level": "LOW",
                "factors": {},
                "breakdown": "Không có CVSS score"
            }

        max_cvss = max(cvss_scores)
        avg_cvss = sum(cvss_scores) / len(cvss_scores)

        # Layer 2: Asset Criticality
        asset_criticality_bonus = {
            "CRITICAL": 1.0,
            "HIGH": 0.8,
            "MEDIUM": 0.5,
            "LOW": 0.2,
        }.get(device_criticality, 0.5)

        if is_dc:
            asset_criticality_bonus = min(1.0, asset_criticality_bonus + 0.3)
        if is_production:
            asset_criticality_bonus = min(1.0, asset_criticality_bonus + 0.2)

        # Layer 3: Exposure
        exposure_bonus = 1.0 if internet_exposed else 0.5

        # Calculate risk score
        risk_score = (
            (max_cvss / 10.0) * 0.35
            + (avg_cvss / 10.0) * 0.15
            + epss_score * 0.15
            + kev_bonus * 0.10
            + exploit_bonus * 0.10
            + asset_criticality_bonus * 0.10
            + exposure_bonus * 0.05
        ) * 100

        risk_level = RiskScorer.classify_risk(min(100.0, risk_score))

        # Build breakdown string
        breakdown = (
            f"Max CVSS: {max_cvss:.1f}/10 × 0.35 = {(max_cvss/10.0)*0.35:.3f}\n"
            f"Avg CVSS: {avg_cvss:.1f}/10 × 0.15 = {(avg_cvss/10.0)*0.15:.3f}\n"
            f"Asset Criticality: {asset_criticality_bonus:.1f} × 0.10 = {asset_criticality_bonus*0.10:.3f}\n"
            f"Exposure: {exposure_bonus:.1f} × 0.05 = {exposure_bonus*0.05:.3f}\n"
            f"---\n"
            f"Total: {(risk_score/100):.4f} × 100 = {risk_score:.1f}"
        )

        return {
            "risk_score": min(100.0, risk_score),
            "risk_level": risk_level,
            "factors": {
                "max_cvss": max_cvss,
                "avg_cvss": avg_cvss,
                "asset_criticality": asset_criticality_bonus,
                "exposure_bonus": exposure_bonus,
            },
            "breakdown": breakdown
        }
