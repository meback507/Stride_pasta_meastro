import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class Methodology(Base):
    __tablename__ = "methodologies"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False) # STRIDE, PASTA, MAESTRO, TARA
    name = Column(String(255), nullable=False)
    category = Column(String(100), default="Methodology") # Methodology, Framework, Standard
    target_domain = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    schema_version = Column(String(20), default="1.0")
    config_json = Column(JSON, nullable=True) # stores categories, layers, stages

    assessments = relationship("Assessment", back_populates="methodology")


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    methodology_id = Column(Integer, ForeignKey("methodologies.id"), nullable=False)
    name = Column(String(255), nullable=False)
    version = Column(String(50), default="v1.0")
    status = Column(String(50), default="draft") # draft, in_review, approved, archived
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="assessments")
    methodology = relationship("Methodology", back_populates="assessments")
    threats = relationship("Threat", back_populates="assessment", cascade="all, delete-orphan")
    llm_runs = relationship("LLMRun", back_populates="assessment", cascade="all, delete-orphan")
