from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.project import Project
from app.models.methodology import Assessment, Methodology
from app.models.threat import Threat, RiskAssessment, Mitigation

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/metrics")
def get_dashboard_metrics(db: Session = Depends(get_db)):
    total_projects = db.query(Project).count()
    total_assessments = db.query(Assessment).count()
    total_threats = db.query(Threat).count()
    approved_threats = db.query(Threat).filter(Threat.review_status == "approved").count()
    
    # Severity breakdown
    risk_records = db.query(RiskAssessment).all()
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    heatmap = [[0 for _ in range(5)] for _ in range(5)] # [likelihood 1-5][impact 1-5]

    for r in risk_records:
        sev = r.severity or "Medium"
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        l_idx = max(0, min(4, (r.likelihood or 3) - 1))
        i_idx = max(0, min(4, (r.impact or 3) - 1))
        heatmap[l_idx][i_idx] += 1

    # Mitigation count
    total_mitigations = db.query(Mitigation).count()
    open_mitigations = db.query(Mitigation).filter(Mitigation.status.in_(["proposed", "planned", "in_progress"])).count()

    # Methodology distribution
    assessments = db.query(Assessment).all()
    methodology_counts = {}
    for a in assessments:
        code = a.methodology.code if a.methodology else "Unknown"
        methodology_counts[code] = methodology_counts.get(code, 0) + 1

    return {
        "total_projects": total_projects,
        "total_assessments": total_assessments,
        "total_threats": total_threats,
        "approved_threats": approved_threats,
        "severity_breakdown": severity_counts,
        "open_mitigations": open_mitigations,
        "total_mitigations": total_mitigations,
        "methodology_distribution": methodology_counts,
        "risk_heatmap": heatmap
    }

