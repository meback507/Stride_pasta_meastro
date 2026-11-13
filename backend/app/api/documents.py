import os
import shutil
import time
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models.project import Project, Document
from app.schemas.project import DocumentResponse
from app.services.document_service import DocumentService

router = APIRouter(prefix="/api/documents", tags=["Documents"])


@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    project_id: int = Query(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    # Safe destination path with timestamp and random token
    clean_name = os.path.basename(file.filename or "uploaded_file").replace(" ", "_")
    safe_filename = f"p{project_id}_{int(time.time())}_{uuid.uuid4().hex[:6]}_{clean_name}"
    target_path = os.path.join(settings.UPLOAD_DIR, safe_filename)

    with open(target_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    file_size = os.path.getsize(target_path)
    file_ext = os.path.splitext(clean_name)[1].lower().replace(".", "")

    # Extract text from uploaded document
    extracted_text = DocumentService.extract_text_from_file(target_path, file_ext)

    doc = Document(
        project_id=project_id,
        filename=file.filename or clean_name,
        file_path=target_path,
        file_type=file_ext,
        file_size=file_size,
        extracted_text=extracted_text,
        doc_metadata={"char_count": len(extracted_text)}
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    return doc


@router.post("/upload-multiple", response_model=List[DocumentResponse], status_code=status.HTTP_201_CREATED)
async def upload_multiple_documents(
    project_id: int = Query(...),
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db)
):
    """
    Ingests and extracts text from multiple architecture specifications, requirements sheets,
    and diagram files simultaneously for unified threat analysis context.
    """
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    created_docs = []

    for file in files:
        if not file.filename:
            continue

        clean_name = os.path.basename(file.filename).replace(" ", "_")
        safe_filename = f"p{project_id}_{int(time.time())}_{uuid.uuid4().hex[:6]}_{clean_name}"
        target_path = os.path.join(settings.UPLOAD_DIR, safe_filename)

        with open(target_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size = os.path.getsize(target_path)
        file_ext = os.path.splitext(clean_name)[1].lower().replace(".", "")

        extracted_text = DocumentService.extract_text_from_file(target_path, file_ext)

        doc = Document(
            project_id=project_id,
            filename=file.filename,
            file_path=target_path,
            file_type=file_ext,
            file_size=file_size,
            extracted_text=extracted_text,
            doc_metadata={"char_count": len(extracted_text)}
        )
        db.add(doc)
        created_docs.append(doc)

    db.commit()
    for d in created_docs:
        db.refresh(d)

    return created_docs


@router.get("/project/{project_id}", response_model=List[DocumentResponse])
def list_project_documents(project_id: int, db: Session = Depends(get_db)):
    docs = db.query(Document).filter(Document.project_id == project_id).all()
    return docs


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_document(document_id: int, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Remove file from disk
    if os.path.exists(doc.file_path):
        try:
            os.remove(doc.file_path)
        except OSError:
            pass

    db.delete(doc)
    db.commit()
    return None

