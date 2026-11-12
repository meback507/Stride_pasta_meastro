from typing import Dict, Any, List


class RiskService:
    @staticmethod
    def calculate_risk_matrix(likelihood: int, impact: int) -> Dict[str, Any]:
        l = max(1, min(5, int(likelihood)))
        i = max(1, min(5, int(impact)))
        score = l * i

        if score >= 20:
            severity = "Critical"
        elif score >= 14:
            severity = "High"
        elif score >= 7:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "likelihood": l,
            "impact": i,
            "inherent_risk": score,
            "severity": severity,
            "risk_treatment": "mitigate" if score >= 10 else "accept"
        }

    @staticmethod
    def calculate_residual_risk(inherent_risk: int, mitigations: List[Dict[str, Any]]) -> int:
        """
        Calculates residual risk factoring in implemented/verified mitigations.
        """
        reduction = 0
        for m in mitigations:
            status = m.get("status", "proposed").lower()
            if status == "verified":
                reduction += 4
            elif status == "implemented":
                reduction += 3
            elif status == "in_progress":
                reduction += 1

        residual = max(1, inherent_risk - reduction)
        return residual

    @staticmethod
    def calculate_tara_risk(feasibility: str, sfop_impact: str) -> Dict[str, Any]:
        """
        ISO/SAE 21434 TARA risk determination.
        """
        feasibility_levels = {"Very Low": 1, "Low": 2, "Medium": 3, "High": 4}
        f_score = feasibility_levels.get(feasibility, 3)

        if "Severe" in sfop_impact:
            i_score = 5
        elif "Major" in sfop_impact:
            i_score = 4
        elif "Moderate" in sfop_impact:
            i_score = 3
        else:
            i_score = 1

        risk_val = max(1, min(5, (f_score * i_score) // 4))
        severity_map = {1: "Low", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

        return {
            "feasibility": feasibility,
            "sfop_impact": sfop_impact,
            "feasibility_score": f_score,
            "impact_score": i_score,
            "tara_risk_value": risk_val,
            "severity": severity_map.get(risk_val, "Medium")
        }
