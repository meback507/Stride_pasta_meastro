import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    business_domain = Column(String(100), default="Enterprise Software")
    technical_scope = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(50), default="active")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="projects")
    members = relationship("ProjectMember", back_populates="project", cascade="all, delete-orphan")
    components = relationship("Component", back_populates="project", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    data_flows = relationship("DataFlow", back_populates="project", cascade="all, delete-orphan")
    documents = relationship("Document", back_populates="project", cascade="all, delete-orphan")
    assessments = relationship("Assessment", back_populates="project", cascade="all, delete-orphan")


class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(String(100), default="Service") # Service, API, Database, Web App, Mobile App, ECU, Agent Worker, Sensor
    description = Column(Text, nullable=True)
    trust_zone = Column(String(100), default="Internal Network")

    project = relationship("Project", back_populates="components")
    threats = relationship("Threat", back_populates="component")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(String(100), default="Data") # Data, Credential, Hardware, Firmware, Process, AI Weights
    sensitivity = Column(String(50), default="High") # Low, Medium, High, Critical
    confidentiality_req = Column(String(50), default="High")
    integrity_req = Column(String(50), default="High")
    availability_req = Column(String(50), default="Medium")

    project = relationship("Project", back_populates="assets")
    threats = relationship("Threat", back_populates="asset")


class DataFlow(Base):
    __tablename__ = "data_flows"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    source_name = Column(String(255), nullable=False)
    target_name = Column(String(255), nullable=False)
    protocol = Column(String(100), default="HTTPS/TLS")
    data_classification = Column(String(100), default="Confidential")
    is_cross_boundary = Column(Boolean, default=False)

    project = relationship("Project", back_populates="data_flows")


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_type = Column(String(50), nullable=False)
    file_size = Column(Integer, default=0)
    extracted_text = Column(Text, nullable=True)
    doc_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="documents")

