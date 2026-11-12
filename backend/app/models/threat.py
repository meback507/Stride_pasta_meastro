import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    component_id = Column(Integer, ForeignKey("components.id", ondelete="SET NULL"), nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    threat_category = Column(String(100), nullable=False) # e.g., Spoofing, Stage IV, Layer 1 Model, or TARA Spoofing
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    attack_vector = Column(Text, nullable=True)
    source_reference = Column(String(255), nullable=True) # document, section or assumed
    is_ai_generated = Column(Boolean, default=True)
    review_status = Column(String(50), default="draft") # draft, reviewed, approved, rejected, mitigated
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    assessment = relationship("Assessment", back_populates="threats")
    component = relationship("Component", back_populates="threats")
    asset = relationship("Asset", back_populates="threats")
    scenarios = relationship("AttackScenario", back_populates="threat", cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessment", back_populates="threat", uselist=False, cascade="all, delete-orphan")
    mitigations = relationship("Mitigation", back_populates="threat", cascade="all, delete-orphan")
    security_requirements = relationship("SecurityRequirement", back_populates="threat", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="threat", cascade="all, delete-orphan")


class AttackScenario(Base):
    __tablename__ = "attack_scenarios"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=False)
    step_order = Column(Integer, default=1)
    description = Column(Text, nullable=False)
    pre_conditions = Column(Text, nullable=True)
    post_conditions = Column(Text, nullable=True)

    threat = relationship("Threat", back_populates="scenarios")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), unique=True, nullable=False)
    likelihood = Column(Integer, default=3) # 1 to 5
    impact = Column(Integer, default=3) # 1 to 5
    inherent_risk = Column(Integer, default=9) # 1 to 25
    residual_risk = Column(Integer, default=6) # 1 to 25
    severity = Column(String(50), default="Medium") # Low, Medium, High, Critical
    
    # Specific fields for ISO/SAE 21434 TARA
    tara_feasibility = Column(String(50), nullable=True) # Very Low, Low, Medium, High
    tara_impact_sfop = Column(String(100), nullable=True) # Safety, Financial, Operational, Privacy vector
    tara_risk_value = Column(Integer, nullable=True) # 1 to 5
    
    risk_treatment = Column(String(50), default="mitigate") # mitigate, accept, transfer, avoid

    threat = relationship("Threat", back_populates="risk_assessment")


class Mitigation(Base):
    __tablename__ = "mitigations"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    mitigation_type = Column(String(100), default="Preventive") # Preventive, Detective, Corrective, Compensating
    implementation_effort = Column(String(50), default="Medium") # Low, Medium, High
    status = Column(String(50), default="proposed") # proposed, planned, in_progress, implemented, verified
    owner = Column(String(255), nullable=True)

    threat = relationship("Threat", back_populates="mitigations")


class SecurityRequirement(Base):
    __tablename__ = "security_requirements"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=False)
    requirement_text = Column(Text, nullable=False)
    standard_ref = Column(String(100), nullable=True) # NIST SP 800-53, ISO 27001, OWASP, ISO 21434
    status = Column(String(50), default="active")

    threat = relationship("Threat", back_populates="security_requirements")


class Review(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=True)
    reviewer_name = Column(String(255), nullable=False)
    comment = Column(Text, nullable=False)
    action = Column(String(50), default="approved") # approved, rejected, changes_requested
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    threat = relationship("Threat", back_populates="reviews")

