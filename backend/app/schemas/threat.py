from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class AttackScenarioSchema(BaseModel):
    step_order: int = 1
    description: str
    pre_conditions: Optional[str] = None
    post_conditions: Optional[str] = None

    class Config:
        from_attributes = True


class RiskAssessmentBase(BaseModel):
    likelihood: int = Field(default=3, ge=1, le=5)
    impact: int = Field(default=3, ge=1, le=5)
    inherent_risk: Optional[int] = 9
    residual_risk: Optional[int] = 6
    severity: Optional[str] = "Medium"
    tara_feasibility: Optional[str] = None # Very Low, Low, Medium, High
    tara_impact_sfop: Optional[str] = None # e.g. "S:Severe, F:Moderate, O:Major, P:Low"
    tara_risk_value: Optional[int] = None
    risk_treatment: str = Field(default="mitigate")


class RiskAssessmentSchema(RiskAssessmentBase):
    id: Optional[int] = None

    class Config:
        from_attributes = True


class MitigationBase(BaseModel):
    title: str
    description: str
    mitigation_type: str = "Preventive"
    implementation_effort: str = "Medium"
    status: str = "proposed"
    owner: Optional[str] = None


class MitigationCreate(MitigationBase):
    pass


class MitigationUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    mitigation_type: Optional[str] = None
    implementation_effort: Optional[str] = None
    status: Optional[str] = None
    owner: Optional[str] = None


class MitigationResponse(MitigationBase):
    id: int
    threat_id: int

    class Config:
        from_attributes = True


class SecurityRequirementSchema(BaseModel):
    id: Optional[int] = None
    requirement_text: str
    standard_ref: Optional[str] = None
    status: str = "active"

    class Config:
        from_attributes = True


class ReviewSchema(BaseModel):
    id: Optional[int] = None
    reviewer_name: str
    comment: str
    action: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ThreatBase(BaseModel):
    threat_category: str = Field(..., example="Tampering")
    title: str = Field(..., example="Man-in-the-Middle Attack on API Gateway Communication")
    description: str
    attack_vector: Optional[str] = None
    source_reference: Optional[str] = "Architecture Document Section 2"
    component_name: Optional[str] = None
    asset_name: Optional[str] = None


class ThreatCreate(ThreatBase):
    component_id: Optional[int] = None
    asset_id: Optional[int] = None
    scenarios: Optional[List[AttackScenarioSchema]] = []
    risk_assessment: Optional[RiskAssessmentBase] = None
    mitigations: Optional[List[MitigationCreate]] = []
    security_requirements: Optional[List[str]] = []


class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    threat_category: Optional[str] = None
    attack_vector: Optional[str] = None
    review_status: Optional[str] = None # draft, reviewed, approved, rejected, mitigated
    likelihood: Optional[int] = None
    impact: Optional[int] = None
    risk_treatment: Optional[str] = None


class ThreatApprovalRequest(BaseModel):
    review_status: str = Field(..., example="approved") # approved, rejected, draft
    reviewer_name: str = Field(default="Security Engineer")
    comment: Optional[str] = "Approved following security review"


class ThreatResponse(ThreatBase):
    id: int
    assessment_id: int
    component_id: Optional[int] = None
    asset_id: Optional[int] = None
    is_ai_generated: bool
    review_status: str
    created_at: datetime
    scenarios: List[AttackScenarioSchema] = []
    risk_assessment: Optional[RiskAssessmentSchema] = None
    mitigations: List[MitigationResponse] = []
    security_requirements: List[SecurityRequirementSchema] = []
    reviews: List[ReviewSchema] = []

    class Config:
        from_attributes = True
