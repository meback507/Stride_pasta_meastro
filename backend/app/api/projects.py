from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.project import Project, Component, Asset, DataFlow
from app.schemas.project import (
    ProjectCreate, ProjectResponse,
    ComponentCreate, ComponentResponse,
    AssetCreate, AssetResponse,
    DataFlowCreate, DataFlowResponse
)

router = APIRouter(prefix="/api/projects", tags=["Projects"])


@router.get("", response_model=List[ProjectResponse])
def list_projects(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.created_at.desc()).offset(skip).limit(limit).all()
    return projects


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(project_in: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(
        name=project_in.name,
        description=project_in.description,
        business_domain=project_in.business_domain,
        technical_scope=project_in.technical_scope
    )
    db.add(project)
    db.flush()

    # Add components if provided
    if project_in.components:
        for c in project_in.components:
            db.add(Component(
                project_id=project.id,
                name=c.name,
                type=c.type,
                description=c.description,
                trust_zone=c.trust_zone
            ))

    # Add assets if provided
    if project_in.assets:
        for a in project_in.assets:
            db.add(Asset(
                project_id=project.id,
                name=a.name,
                type=a.type,
                sensitivity=a.sensitivity,
                confidentiality_req=a.confidentiality_req,
                integrity_req=a.integrity_req,
                availability_req=a.availability_req
            ))

    # Add data flows if provided
    if project_in.data_flows:
        for df in project_in.data_flows:
            db.add(DataFlow(
                project_id=project.id,
                source_name=df.source_name,
                target_name=df.target_name,
                protocol=df.protocol,
                data_classification=df.data_classification,
                is_cross_boundary=df.is_cross_boundary
            ))

    db.commit()
    db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()
    return None


@router.post("/{project_id}/components", response_model=ComponentResponse)
def add_component(project_id: int, comp_in: ComponentCreate, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    comp = Component(
        project_id=project_id,
        name=comp_in.name,
        type=comp_in.type,
        description=comp_in.description,
        trust_zone=comp_in.trust_zone
    )
    db.add(comp)
    db.commit()
    db.refresh(comp)
    return comp


@router.post("/{project_id}/assets", response_model=AssetResponse)
def add_asset(project_id: int, asset_in: AssetCreate, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    asset = Asset(
        project_id=project_id,
        name=asset_in.name,
        type=asset_in.type,
        sensitivity=asset_in.sensitivity,
        confidentiality_req=asset_in.confidentiality_req,
        integrity_req=asset_in.integrity_req,
        availability_req=asset_in.availability_req
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.post("/{project_id}/data-flows", response_model=DataFlowResponse)
def add_data_flow(project_id: int, df_in: DataFlowCreate, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    df = DataFlow(
        project_id=project_id,
        source_name=df_in.source_name,
        target_name=df_in.target_name,
        protocol=df_in.protocol,
        data_classification=df_in.data_classification,
        is_cross_boundary=df_in.is_cross_boundary
    )
    db.add(df)
    db.commit()
    db.refresh(df)
    return df

