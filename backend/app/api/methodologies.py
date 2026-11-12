from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.methodology import Methodology
from app.schemas.methodology import MethodologyResponse
from app.methodologies.factory import MethodologyFactory

router = APIRouter(prefix="/api/methodologies", tags=["Methodologies"])


@router.get("", response_model=List[MethodologyResponse])
def list_methodologies(db: Session = Depends(get_db)):
    methodologies = db.query(Methodology).all()
    # Enrich with live factory metadata if needed
    result = []
    for m in methodologies:
        engine = MethodologyFactory.get_engine(m.code)
        m_dict = {
            "id": m.id,
            "code": m.code,
            "name": m.name,
            "category": m.category,
            "target_domain": m.target_domain,
            "description": m.description,
            "schema_version": m.schema_version,
            "config_json": {
                "categories": engine.get_categories(),
                "category_type": engine.category_type
            }
        }
        result.append(m_dict)
    return result


@router.get("/{code}", response_model=MethodologyResponse)
def get_methodology(code: str, db: Session = Depends(get_db)):
    m = db.query(Methodology).filter(Methodology.code == code.upper()).first()
    if not m:
        raise HTTPException(status_code=404, detail="Methodology not found")
    engine = MethodologyFactory.get_engine(m.code)
    return {
        "id": m.id,
        "code": m.code,
        "name": m.name,
        "category": m.category,
        "target_domain": m.target_domain,
        "description": m.description,
        "schema_version": m.schema_version,
        "config_json": {
            "categories": engine.get_categories(),
            "category_type": engine.category_type
        }
    }
