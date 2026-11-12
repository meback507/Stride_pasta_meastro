from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.threat import Threat, RiskAssessment, Mitigation, Review
from app.schemas.threat import (
    ThreatUpdate, ThreatResponse, ThreatApprovalRequest,
    MitigationCreate, MitigationResponse, MitigationUpdate
)
from app.services.risk_service import RiskService

router = APIRouter(prefix="/api/threats", tags=["Threat Register"])


@router.get("/{threat_id}", response_model=ThreatResponse)
def get_threat(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@router.put("/{threat_id}", response_model=ThreatResponse)
def update_threat(threat_id: int, threat_in: ThreatUpdate, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    if threat_in.title is not None:
        threat.title = threat_in.title
    if threat_in.description is not None:
        threat.description = threat_in.description
    if threat_in.threat_category is not None:
        threat.threat_category = threat_in.threat_category
    if threat_in.attack_vector is not None:
        threat.attack_vector = threat_in.attack_vector
    if threat_in.review_status is not None:
        threat.review_status = threat_in.review_status

    # Recalculate risk if likelihood or impact are modified
    if threat_in.likelihood is not None or threat_in.impact is not None:
        ra = threat.risk_assessment
        if not ra:
            ra = RiskAssessment(threat_id=threat.id)
            db.add(ra)

        cur_l = threat_in.likelihood if threat_in.likelihood is not None else ra.likelihood
        cur_i = threat_in.impact if threat_in.impact is not None else ra.impact
        
        calc = RiskService.calculate_risk_matrix(cur_l, cur_i)
        ra.likelihood = calc["likelihood"]
        ra.impact = calc["impact"]
        ra.inherent_risk = calc["inherent_risk"]
        ra.severity = calc["severity"]
        if threat_in.risk_treatment:
            ra.risk_treatment = threat_in.risk_treatment
        else:
            ra.risk_treatment = calc["risk_treatment"]

        # Recompute residual risk
        mits_dict = [{"status": m.status} for m in threat.mitigations]
        ra.residual_risk = RiskService.calculate_residual_risk(ra.inherent_risk, mits_dict)

    db.commit()
    db.refresh(threat)
    return threat


@router.post("/{threat_id}/approve", response_model=ThreatResponse)
def approve_or_review_threat(threat_id: int, req: ThreatApprovalRequest, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    threat.review_status = req.review_status

    # Record review audit log
    review = Review(
        assessment_id=threat.assessment_id,
        threat_id=threat.id,
        reviewer_name=req.reviewer_name,
        comment=req.comment or f"Status set to {req.review_status}",
        action=req.review_status
    )
    db.add(review)

    db.commit()
    db.refresh(threat)
    return threat


@router.post("/{threat_id}/mitigations", response_model=MitigationResponse, status_code=status.HTTP_201_CREATED)
def add_mitigation(threat_id: int, mit_in: MitigationCreate, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    mit = Mitigation(
        threat_id=threat_id,
        title=mit_in.title,
        description=mit_in.description,
        mitigation_type=mit_in.mitigation_type,
        implementation_effort=mit_in.implementation_effort,
        status=mit_in.status,
        owner=mit_in.owner
    )
    db.add(mit)
    db.flush()

    # Recalculate residual risk
    if threat.risk_assessment:
        mits = db.query(Mitigation).filter(Mitigation.threat_id == threat_id).all()
        threat.risk_assessment.residual_risk = RiskService.calculate_residual_risk(
            threat.risk_assessment.inherent_risk, [{"status": m.status} for m in mits]
        )

    db.commit()
    db.refresh(mit)
    return mit


@router.put("/mitigations/{mitigation_id}", response_model=MitigationResponse)
def update_mitigation(mitigation_id: int, mit_in: MitigationUpdate, db: Session = Depends(get_db)):
    mit = db.query(Mitigation).filter(Mitigation.id == mitigation_id).first()
    if not mit:
        raise HTTPException(status_code=404, detail="Mitigation not found")

    if mit_in.title is not None:
        mit.title = mit_in.title
    if mit_in.description is not None:
        mit.description = mit_in.description
    if mit_in.mitigation_type is not None:
        mit.mitigation_type = mit_in.mitigation_type
    if mit_in.implementation_effort is not None:
        mit.implementation_effort = mit_in.implementation_effort
    if mit_in.status is not None:
        mit.status = mit_in.status
    if mit_in.owner is not None:
        mit.owner = mit_in.owner

    db.flush()

    # Recalculate parent threat residual risk
    threat = mit.threat
    if threat and threat.risk_assessment:
        mits = db.query(Mitigation).filter(Mitigation.threat_id == threat.id).all()
        threat.risk_assessment.residual_risk = RiskService.calculate_residual_risk(
            threat.risk_assessment.inherent_risk, [{"status": m.status} for m in mits]
        )

    db.commit()
    db.refresh(mit)
    return mit


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_threat(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    db.delete(threat)
    db.commit()
    return None

