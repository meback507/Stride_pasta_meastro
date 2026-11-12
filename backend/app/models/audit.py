import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class LLMRun(Base):
    __tablename__ = "llm_runs"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False) # openai, ollama, simulation
    model_name = Column(String(100), nullable=False)
    prompt_version = Column(String(50), default="1.0")
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    status = Column(String(50), default="success") # success, failed
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    assessment = relationship("Assessment", back_populates="llm_runs")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    user_email = Column(String(255), default="system")
    action = Column(String(100), nullable=False) # CREATE_PROJECT, ANALYZE_ASSESSMENT, APPROVE_THREAT, etc.
    entity_type = Column(String(50), nullable=False) # project, threat, assessment, mitigation
    entity_id = Column(Integer, nullable=False)
    change_diff = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
