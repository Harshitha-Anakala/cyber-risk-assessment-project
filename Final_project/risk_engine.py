def calculate_risk(scan_data, threat_data):
    try:
        # ---------------- COMPONENTS ---------------- #

        open_ports = len(scan_data.get("ports", []))  # ✅ FIXED
        exposure_score = min(open_ports / 10, 1) * 10

        threat_score = threat_data.get("threat_score", 0)  # ✅ FIXED

        context_score = 5

        # ---------------- FINAL RISK ---------------- #

        risk_score = (
            0.5 * exposure_score +
            0.3 * threat_score +
            0.2 * context_score
        )

        # ---------------- SEVERITY ---------------- #

        if risk_score >= 8:
            severity = "Critical"
        elif risk_score >= 6:
            severity = "High"
        elif risk_score >= 3:
            severity = "Medium"
        else:
            severity = "Low"

        # ---------------- RECOMMENDATIONS ---------------- #

        recommendations = []

        if open_ports > 5:
            recommendations.append("Reduce number of open ports")

        if threat_score > 5:
            recommendations.append("Investigate malicious activity")

        if risk_score >= 8:
            recommendations.append("Immediate action required")

        if not recommendations:
            recommendations.append("System looks safe")

        return {
            "risk_score": round(risk_score, 2),
            "severity": severity,
            "exposure_score": round(exposure_score, 2),
            "threat_score": threat_score,
            "recommendations": recommendations
        }

    except Exception as e:
        return {
            "risk_score": 0,
            "severity": "Unknown",
            "error": str(e)
        }