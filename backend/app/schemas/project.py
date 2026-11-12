from typing import List, Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field


class ComponentBase(BaseModel):
    name: str = Field(..., example="User Authentication Gateway")
    type: str = Field(default="Service", example="Service")
    description: Optional[str] = Field(None, example="Handles JWT signing and OAuth2 verification")
    trust_zone: str = Field(default="DMZ", example="DMZ")


class ComponentCreate(ComponentBase):
    pass


class ComponentResponse(ComponentBase):
    id: int
    project_id: int

    class Config:
        from_attributes = True


class AssetBase(BaseModel):
    name: str = Field(..., example="Customer PII Database")
    type: str = Field(default="Data", example="Data")
    sensitivity: str = Field(default="High", example="High")
    confidentiality_req: str = Field(default="High", example="High")
    integrity_req: str = Field(default="High", example="High")
    availability_req: str = Field(default="Medium", example="Medium")


class AssetCreate(AssetBase):
    pass


class AssetResponse(AssetBase):
    id: int
    project_id: int

    class Config:
        from_attributes = True


class DataFlowBase(BaseModel):
    source_name: str = Field(..., example="Frontend Web App")
    target_name: str = Field(..., example="API Gateway")
    protocol: str = Field(default="HTTPS/REST", example="HTTPS/REST")
    data_classification: str = Field(default="Confidential", example="Confidential")
    is_cross_boundary: bool = Field(default=True)


class DataFlowCreate(DataFlowBase):
    pass


class DataFlowResponse(DataFlowBase):
    id: int
    project_id: int

    class Config:
        from_attributes = True


class DocumentResponse(BaseModel):
    id: int
    project_id: int
    filename: str
    file_type: str
    file_size: int
    extracted_text: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ProjectBase(BaseModel):
    name: str = Field(..., example="Autonomous Fleet Management Platform")
    description: Optional[str] = Field(None, example="Central telematics & microservices platform for connected vehicles")
    business_domain: str = Field(default="Automotive & Cloud", example="Automotive & Cloud")
    technical_scope: Optional[str] = Field(None, example="In-vehicle gateway, cloud ingestion pipeline, and customer portal")


class ProjectCreate(ProjectBase):
    components: Optional[List[ComponentCreate]] = []
    assets: Optional[List[AssetCreate]] = []
    data_flows: Optional[List[DataFlowCreate]] = []


class ProjectResponse(ProjectBase):
    id: int
    owner_id: Optional[int] = None
    status: str
    created_at: datetime
    updated_at: datetime
    components: List[ComponentResponse] = []
    assets: List[AssetResponse] = []
    data_flows: List[DataFlowResponse] = []
    documents: List[DocumentResponse] = []

    class Config:
        from_attributes = True

