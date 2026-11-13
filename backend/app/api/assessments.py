from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.project import Project, Component, Asset, Document
from app.models.methodology import Methodology, Assessment
from app.models.threat import Threat, AttackScenario, RiskAssessment, Mitigation, SecurityRequirement
from app.models.audit import LLMRun
from app.schemas.methodology import (
    AssessmentCreate, AssessmentResponse, AIAnalysisRequest, AIAnalysisResponse,
    CodeSnippetAnalysisRequest, CodeSnippetAnalysisResponse
)
from app.methodologies.factory import MethodologyFactory
from app.services.llm_service import LLMService

router = APIRouter(prefix="/api/assessments", tags=["Assessments"])


@router.post("", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
def create_assessment(item_in: AssessmentCreate, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == item_in.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    methodology = db.query(Methodology).filter(Methodology.code == item_in.methodology_code.upper()).first()
    if not methodology:
        raise HTTPException(status_code=404, detail=f"Methodology '{item_in.methodology_code}' not found")

    assessment = Assessment(
        project_id=item_in.project_id,
        methodology_id=methodology.id,
        name=item_in.name,
        version=item_in.version,
        status="draft",
        summary=f"Threat model initiated using {methodology.name}."
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    return {
        "id": assessment.id,
        "project_id": assessment.project_id,
        "methodology_id": assessment.methodology_id,
        "methodology_code": methodology.code,
        "methodology_name": methodology.name,
        "name": assessment.name,
        "version": assessment.version,
        "status": assessment.status,
        "summary": assessment.summary,
        "created_at": assessment.created_at,
        "updated_at": assessment.updated_at,
        "threat_count": 0,
        "threats": []
    }


@router.get("/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(assessment_id: int, db: Session = Depends(get_db)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    threats = db.query(Threat).filter(Threat.assessment_id == assessment_id).all()
    
    return {
        "id": assessment.id,
        "project_id": assessment.project_id,
        "methodology_id": assessment.methodology_id,
        "methodology_code": assessment.methodology.code,
        "methodology_name": assessment.methodology.name,
        "name": assessment.name,
        "version": assessment.version,
        "status": assessment.status,
        "summary": assessment.summary,
        "created_at": assessment.created_at,
        "updated_at": assessment.updated_at,
        "threat_count": len(threats),
        "threats": threats
    }


@router.post("/{assessment_id}/analyze", response_model=AIAnalysisResponse)
async def run_ai_analysis(
    assessment_id: int,
    req: AIAnalysisRequest,
    db: Session = Depends(get_db)
):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    project = db.query(Project).filter(Project.id == assessment.project_id).first()
    methodology_code = assessment.methodology.code
    engine = MethodologyFactory.get_engine(methodology_code)

    # Compile project data
    project_data = {
        "name": project.name,
        "business_domain": project.business_domain,
        "technical_scope": project.technical_scope,
        "components": [{"name": c.name, "type": c.type, "trust_zone": c.trust_zone, "description": c.description} for c in project.components],
        "assets": [{"name": a.name, "type": a.type, "sensitivity": a.sensitivity, "confidentiality_req": a.confidentiality_req, "integrity_req": a.integrity_req, "availability_req": a.availability_req} for a in project.assets],
        "data_flows": [{"source_name": df.source_name, "target_name": df.target_name, "protocol": df.protocol, "is_cross_boundary": df.is_cross_boundary} for df in project.data_flows]
    }

    # Aggregate document context
    documents = db.query(Document).filter(Document.project_id == project.id).all()
    doc_context = "\n\n".join([f"=== Document: {d.filename} ===\n{d.extracted_text or ''}" for d in documents])

    # Run LLM analysis
    ai_result = await LLMService.generate_threats(
        engine=engine,
        project_data=project_data,
        document_context=doc_context,
        provider=req.provider,
        model_name=req.model_name,
        depth=req.depth or "comprehensive",
        focus_areas=req.focus_areas,
        custom_instructions=req.custom_instructions
    )

    # Save LLM Run metadata
    llm_run = LLMRun(
        assessment_id=assessment.id,
        provider=ai_result["provider_used"],
        model_name=ai_result["model_used"],
        latency_ms=ai_result["execution_time_ms"],
        prompt_tokens=ai_result["prompt_tokens"],
        completion_tokens=ai_result["completion_tokens"],
        status=ai_result["status"],
        error_message=ai_result.get("error_message")
    )
    db.add(llm_run)

    # Persist generated threats
    component_map = {c.name.lower(): c.id for c in project.components}
    asset_map = {a.name.lower(): a.id for a in project.assets}

    for raw_t in ai_result["threats"]:
        target_comp_id = component_map.get(raw_t.get("component_name", "").lower())
        target_asset_id = asset_map.get(raw_t.get("asset_name", "").lower())

        threat = Threat(
            assessment_id=assessment.id,
            component_id=target_comp_id,
            asset_id=target_asset_id,
            threat_category=raw_t.get("threat_category", "Identified Threat"),
            title=raw_t.get("title", "Untitled Threat"),
            description=raw_t.get("description", ""),
            attack_vector=raw_t.get("attack_vector"),
            source_reference=raw_t.get("source_reference", "AI Architecture Analysis"),
            is_ai_generated=True,
            review_status="draft"
        )
        db.add(threat)
        db.flush()

        # Attack scenario
        scen = raw_t.get("attack_scenario")
        if scen and isinstance(scen, dict):
            db.add(AttackScenario(
                threat_id=threat.id,
                step_order=1,
                description=scen.get("description", ""),
                pre_conditions=scen.get("pre_conditions"),
                post_conditions=scen.get("post_conditions")
            ))

        # Risk assessment
        ra = raw_t.get("risk_assessment", {})
        db.add(RiskAssessment(
            threat_id=threat.id,
            likelihood=ra.get("likelihood", 3),
            impact=ra.get("impact", 3),
            inherent_risk=ra.get("inherent_risk", 9),
            residual_risk=ra.get("residual_risk", 6),
            severity=ra.get("severity", "Medium"),
            tara_feasibility=raw_t.get("tara_feasibility"),
            tara_impact_sfop=raw_t.get("tara_impact_sfop"),
            tara_risk_value=ra.get("tara_risk_value"),
            risk_treatment=ra.get("risk_treatment", "mitigate")
        ))

        # Mitigations
        for m in raw_t.get("mitigations", []):
            db.add(Mitigation(
                threat_id=threat.id,
                title=m.get("title", "Mitigation Control"),
                description=m.get("description", ""),
                mitigation_type=m.get("mitigation_type", "Preventive"),
                implementation_effort=m.get("effort", "Medium"),
                status="proposed"
            ))

        # Security Requirements
        sec_req = raw_t.get("security_requirement")
        if sec_req:
            db.add(SecurityRequirement(
                threat_id=threat.id,
                requirement_text=sec_req,
                standard_ref=methodology_code
            ))

    assessment.status = "in_review"
    assessment.summary = f"Identified {len(ai_result['threats'])} threats using {engine.name} ({ai_result['model_used']})."
    db.commit()

    return {
        "assessment_id": assessment.id,
        "methodology": engine.name,
        "status": "completed",
        "threats_generated": len(ai_result["threats"]),
        "execution_time_ms": ai_result["execution_time_ms"],
        "summary": assessment.summary,
        "provider_used": ai_result["provider_used"],
        "model_used": ai_result["model_used"]
    }


@router.post("/analyze-code-snippet", response_model=CodeSnippetAnalysisResponse)
async def analyze_code_snippet(req: CodeSnippetAnalysisRequest, db: Session = Depends(get_db)):
    """
    Performs threat modeling directly on a pasted source code snippet.
    """
    # 1. Resolve or create project
    if req.project_id:
        project = db.query(Project).filter(Project.id == req.project_id).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
    else:
        project = db.query(Project).filter(Project.name == "Code Snippet Threat Models").first()
        if not project:
            project = Project(
                name="Code Snippet Threat Models",
                business_domain="Source Code Review",
                technical_scope="Static analysis and code-level threat assessments on pasted source code snippets.",
                status="active"
            )
            db.add(project)
            db.flush()

    # 2. Intelligent Code Understanding & Methodology Selection
    classification = await LLMService.classify_code_and_methodology(
        code_snippet=req.code,
        language=req.language or "auto",
        provider=req.provider,
        model_name=req.model_name
    )

    req_meth = (req.methodology_code or "AUTO").strip().upper()
    if req_meth in ["AUTO", "AUTO-DETECT", "AUTO_DETECT", "DEFAULT", ""]:
        meth_code = classification["selected_methodology"]
        rationale = classification["rationale"]
    else:
        meth_code = req_meth
        rationale = f"User specified {req_meth}. AI detected domain: {classification['detected_domain']} ({classification['code_purpose_summary']})."

    methodology = db.query(Methodology).filter(Methodology.code == meth_code).first()
    if not methodology:
        methodology = db.query(Methodology).filter(Methodology.code == "STRIDE").first()

    engine = MethodologyFactory.get_engine(meth_code)

    # 3. Create Component for snippet
    comp_name = req.snippet_title or "Pasted Code Snippet"
    comp = Component(
        project_id=project.id,
        name=comp_name,
        type=f"Code Module ({req.language})",
        trust_zone="Application Layer",
        description=f"Source snippet ({req.language})"
    )
    db.add(comp)
    db.flush()

    # 4. Create Assessment
    assessment = Assessment(
        project_id=project.id,
        methodology_id=methodology.id,
        name=f"Code Threat Model ({engine.code}): {comp_name}",
        version="v1.0",
        status="in_review",
        summary=f"Code-level threat model on {comp_name} ({req.language}) using {engine.name}."
    )
    db.add(assessment)
    db.flush()

    # 5. Run Code Threat Analysis
    ai_result = await LLMService.generate_code_threats(
        engine=engine,
        code_snippet=req.code,
        language=req.language or "auto",
        snippet_title=comp_name,
        provider=req.provider,
        model_name=req.model_name,
        custom_instructions=req.custom_instructions
    )

    # 6. Save LLM Run metadata
    llm_run = LLMRun(
        assessment_id=assessment.id,
        provider=ai_result["provider_used"],
        model_name=ai_result["model_used"],
        latency_ms=ai_result["execution_time_ms"],
        prompt_tokens=ai_result["prompt_tokens"],
        completion_tokens=ai_result["completion_tokens"],
        status=ai_result["status"],
        error_message=ai_result.get("error_message")
    )
    db.add(llm_run)

    # 7. Persist threats
    persisted_threats = []
    for raw_t in ai_result["threats"]:
        threat = Threat(
            assessment_id=assessment.id,
            component_id=comp.id,
            threat_category=raw_t.get("threat_category", "Code Flaw"),
            title=raw_t.get("title", "Untitled Code Threat"),
            description=raw_t.get("description", ""),
            attack_vector=raw_t.get("attack_vector"),
            source_reference=raw_t.get("source_reference", "Code Snippet"),
            is_ai_generated=True,
            review_status="draft"
        )
        db.add(threat)
        db.flush()

        scen = raw_t.get("attack_scenario")
        if scen and isinstance(scen, dict):
            db.add(AttackScenario(
                threat_id=threat.id,
                step_order=1,
                description=scen.get("description", ""),
                pre_conditions=scen.get("pre_conditions"),
                post_conditions=scen.get("post_conditions")
            ))

        ra = raw_t.get("risk_assessment", {})
        db.add(RiskAssessment(
            threat_id=threat.id,
            likelihood=ra.get("likelihood", 3),
            impact=ra.get("impact", 4),
            inherent_risk=ra.get("inherent_risk", 12),
            residual_risk=ra.get("residual_risk", 6),
            severity=ra.get("severity", "Medium"),
            risk_treatment=ra.get("risk_treatment", "mitigate")
        ))

        for m in raw_t.get("mitigations", []):
            db.add(Mitigation(
                threat_id=threat.id,
                title=m.get("title", "Code Remediation"),
                description=m.get("description", ""),
                mitigation_type=m.get("mitigation_type", "Preventive"),
                implementation_effort=m.get("effort", "Low"),
                status="proposed"
            ))

        sec_req = raw_t.get("security_requirement")
        if sec_req:
            db.add(SecurityRequirement(
                threat_id=threat.id,
                requirement_text=sec_req,
                standard_ref="CWE / Secure Coding Guidelines"
            ))

        persisted_threats.append(threat)

    db.commit()

    return {
        "assessment_id": assessment.id,
        "project_id": project.id,
        "snippet_title": comp_name,
        "language": req.language or "auto",
        "methodology": engine.name,
        "status": "completed",
        "threats_generated": len(persisted_threats),
        "execution_time_ms": ai_result["execution_time_ms"],
        "summary": assessment.summary,
        "code_purpose_summary": classification.get("code_purpose_summary"),
        "selected_methodology_rationale": rationale,
        "detected_domain": classification.get("detected_domain"),
        "provider_used": ai_result["provider_used"],
        "model_used": ai_result["model_used"],
        "threats": persisted_threats
    }

