import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.config import settings
from app.database import Base, engine, SessionLocal
from app.models.user import User
from app.models.methodology import Methodology
from app.models.project import Project, Component, Asset, DataFlow
from app.models.threat import Threat, RiskAssessment, Mitigation
from app.api import auth, projects, methodologies, assessments, threats, documents, reports, dashboard
from app.api.auth import hash_password

# Initialize tables
Base.metadata.create_all(bind=engine)


def seed_database():
    db = SessionLocal()
    try:
        # Seed Methodologies if not present
        if db.query(Methodology).count() == 0:
            methodologies_seed = [
                Methodology(
                    code="STRIDE",
                    name="STRIDE Threat Modeling",
                    category="Technical Threat Modeling",
                    target_domain="Software, Web Applications, Cloud Services & Embedded Systems",
                    description="Decomposes threats into Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.",
                    schema_version="1.0"
                ),
                Methodology(
                    code="PASTA",
                    name="PASTA (Process for Attack Simulation & Threat Analysis)",
                    category="Risk-Centric Framework",
                    target_domain="Enterprise Applications, Multi-tier Systems & Business-Critical Assets",
                    description="Seven-stage risk-centric methodology aligning business objectives, threat actors, attack modeling, and business impact.",
                    schema_version="1.0"
                ),
                Methodology(
                    code="MAESTRO",
                    name="MAESTRO Agentic AI Threat Modeling",
                    category="Agentic AI Cybersecurity Framework",
                    target_domain="Autonomous Agents, LLM Pipelines, Multi-Agent Swarms & RAG Architectures",
                    description="Seven-layer AI threat analysis framework covering Foundation Models, Autonomous Agents, Tools, Memory, Transport, Swarms, and UI.",
                    schema_version="1.0"
                ),
                Methodology(
                    code="TARA",
                    name="ISO/SAE 21434 TARA (Automotive Cybersecurity)",
                    category="Automotive Engineering Standard",
                    target_domain="Automotive Electronic Control Units (ECUs), Telematics, Gateways & Connected Vehicles",
                    description="Evaluates Item definitions, assets with C-I-A properties, SFOP damage scenarios, attack feasibility, and derived cybersecurity goals.",
                    schema_version="1.0"
                )
            ]
            db.add_all(methodologies_seed)
            db.commit()

        # Seed default Admin User if not present
        if db.query(User).count() == 0:
            admin_user = User(
                email="admin@threatmodel.local",
                full_name="Security Architect Lead",
                hashed_password=hash_password("admin123"),
                role="admin"
            )
            db.add(admin_user)
            db.commit()

        # Seed initial showcase project if database is empty
        if db.query(Project).count() == 0:
            sample_project = Project(
                name="Cloud & Autonomous Vehicle Telematics Hub",
                business_domain="Automotive & Cloud Infrastructure",
                technical_scope="Central vehicle gateway, edge telematics control unit (TCU), cloud microservices, and AI fleet dispatch agent.",
                owner_id=1,
                status="active"
            )
            db.add(sample_project)
            db.flush()

            # Components
            c1 = Component(project_id=sample_project.id, name="Telematics Gateway (TCU)", type="ECU / Gateway", trust_zone="Vehicle Edge / External")
            c2 = Component(project_id=sample_project.id, name="Cloud API Ingestion Gateway", type="Microservice", trust_zone="DMZ")
            c3 = Component(project_id=sample_project.id, name="Autonomous Fleet Dispatch Agent", type="AI Agent Worker", trust_zone="Internal VPC")
            c4 = Component(project_id=sample_project.id, name="Powertrain & Braking CAN Bus", type="Vehicle Bus", trust_zone="Safety Critical")
            db.add_all([c1, c2, c3, c4])

            # Assets
            a1 = Asset(project_id=sample_project.id, name="Vehicle Actuation Commands (Brake/Steer)", type="Safety Signal", sensitivity="Critical")
            a2 = Asset(project_id=sample_project.id, name="Telemetry & Customer GPS Trajectories", type="PII Data", sensitivity="High")
            a3 = Asset(project_id=sample_project.id, name="Dispatch Model Weights & Context Memory", type="AI Model", sensitivity="High")
            db.add_all([a1, a2, a3])

            # Data flows
            df1 = DataFlow(project_id=sample_project.id, source_name="Telematics Gateway (TCU)", target_name="Cloud API Ingestion Gateway", protocol="MQTT over TLS 1.3", is_cross_boundary=True)
            df2 = DataFlow(project_id=sample_project.id, source_name="Telematics Gateway (TCU)", target_name="Powertrain & Braking CAN Bus", protocol="CAN-FD (SecOC)", is_cross_boundary=True)
            df3 = DataFlow(project_id=sample_project.id, source_name="Cloud API Ingestion Gateway", target_name="Autonomous Fleet Dispatch Agent", protocol="gRPC / mTLS", is_cross_boundary=False)
            db.add_all([df1, df2, df3])

            db.commit()

    finally:
        db.close()


seed_database()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="LLM-Powered Multi-Framework Cybersecurity Threat Modeling Platform supporting STRIDE, PASTA, MAESTRO, and ISO/SAE 21434 TARA.",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(methodologies.router)
app.include_router(assessments.router)
app.include_router(threats.router)
app.include_router(documents.router)
app.include_router(reports.router)
app.include_router(dashboard.router)


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "supported_methodologies": ["STRIDE", "PASTA", "MAESTRO", "ISO/SAE 21434 TARA"],
        "default_llm_provider": settings.DEFAULT_LLM_PROVIDER
    }


# Static files & SPA fallback
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Don't intercept API routes
        if full_path.startswith("api/") or full_path.startswith("health") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            return None
        index_file = os.path.join(static_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "AI ThreatModel Studio Backend API is live. Visit /docs for OpenAPI specs."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
