from typing import List, Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field
from app.schemas.threat import ThreatResponse


class MethodologyResponse(BaseModel):
    id: int
    code: str
    name: str
    category: str
    target_domain: str
    description: str
    schema_version: str
    config_json: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class AssessmentCreate(BaseModel):
    project_id: int
    methodology_code: str = Field(..., example="STRIDE") # STRIDE, PASTA, MAESTRO, TARA
    name: str = Field(..., example="Phase 1 Architecture Threat Assessment")
    version: str = Field(default="v1.0")


class AssessmentResponse(BaseModel):
    id: int
    project_id: int
    methodology_id: int
    methodology_code: Optional[str] = None
    methodology_name: Optional[str] = None
    name: str
    version: str
    status: str
    summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    threat_count: Optional[int] = 0
    threats: Optional[List[ThreatResponse]] = []

    class Config:
        from_attributes = True


class AIAnalysisRequest(BaseModel):
    provider: Optional[str] = Field(default="simulation", example="simulation") # simulation, openai, ollama
    model_name: Optional[str] = Field(default=None, example="gpt-4o")
    depth: Optional[str] = Field(default="comprehensive", example="comprehensive") # rapid, standard, comprehensive
    focus_areas: Optional[List[str]] = []
    custom_instructions: Optional[str] = None


class AIAnalysisResponse(BaseModel):
    assessment_id: int
    methodology: str
    status: str
    threats_generated: int
    execution_time_ms: int
    summary: str
    provider_used: str
    model_used: str
