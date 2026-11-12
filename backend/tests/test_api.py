import os
import pytest
from fastapi.testclient import TestClient
import sys

# Ensure backend path is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from app.database import SessionLocal
from app.models.methodology import Methodology

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "STRIDE" in data["supported_methodologies"]
    assert "PASTA" in data["supported_methodologies"]
    assert "MAESTRO" in data["supported_methodologies"]
    assert "ISO/SAE 21434 TARA" in data["supported_methodologies"]


def test_list_methodologies():
    response = client.get("/api/methodologies")
    assert response.status_code == 200
    methodologies = response.json()
    codes = [m["code"] for m in methodologies]
    assert "STRIDE" in codes
    assert "PASTA" in codes
    assert "MAESTRO" in codes
    assert "TARA" in codes


def test_project_lifecycle():
    # 1. Create Project
    project_payload = {
        "name": "Connected Autonomous Vehicle Subsystem",
        "business_domain": "Automotive Engineering",
        "technical_scope": "V2X Telematics, Central Gateway ECU, Powertrain CAN-FD",
        "components": [
            {"name": "Telematics Unit", "type": "ECU", "trust_zone": "Vehicle Edge"},
            {"name": "Braking Controller", "type": "Safety ECU", "trust_zone": "Chassis Zone"}
        ],
        "assets": [
            {"name": "Braking Signal", "type": "Actuation Signal", "sensitivity": "Critical"}
        ],
        "data_flows": [
            {"source_name": "Telematics Unit", "target_name": "Braking Controller", "protocol": "CAN-FD", "is_cross_boundary": True}
        ]
    }
    create_res = client.post("/api/projects", json=project_payload)
    assert create_res.status_code == 201
    project_data = create_res.json()
    project_id = project_data["id"]
    assert project_data["name"] == project_payload["name"]
    assert len(project_data["components"]) == 2

    # 2. Test Threat Modeling for each methodology: STRIDE, PASTA, MAESTRO, TARA
    for meth_code in ["STRIDE", "PASTA", "MAESTRO", "TARA"]:
        # Create Assessment
        ass_res = client.post("/api/assessments", json={
            "project_id": project_id,
            "methodology_code": meth_code,
            "name": f"Comprehensive {meth_code} Assessment",
            "version": "v1.0"
        })
        assert ass_res.status_code == 201
        assessment_id = ass_res.json()["id"]

        # Run AI Analysis (Simulation provider for fast, reliable verification)
        analyze_res = client.post(f"/api/assessments/{assessment_id}/analyze", json={
            "provider": "simulation",
            "depth": "comprehensive"
        })
        assert analyze_res.status_code == 200
        analysis_data = analyze_res.json()
        assert analysis_data["status"] == "completed"
        assert analysis_data["threats_generated"] > 0

        # Retrieve Assessment Details
        get_ass_res = client.get(f"/api/assessments/{assessment_id}")
        assert get_ass_res.status_code == 200
        ass_detail = get_ass_res.json()
        assert len(ass_detail["threats"]) > 0

        first_threat = ass_detail["threats"][0]
        threat_id = first_threat["id"]

        # Test Threat Editing
        update_res = client.put(f"/api/threats/{threat_id}", json={
            "likelihood": 4,
            "impact": 5,
            "risk_treatment": "mitigate"
        })
        assert update_res.status_code == 200
        assert update_res.json()["risk_assessment"]["inherent_risk"] == 20

        # Test Approval Workflow
        approve_res = client.post(f"/api/threats/{threat_id}/approve", json={
            "review_status": "approved",
            "reviewer_name": "Chief Security Architect",
            "comment": "Verified against threat criteria"
        })
        assert approve_res.status_code == 200
        assert approve_res.json()["review_status"] == "approved"

        # Test Report Exports
        # JSON
        json_report_res = client.get(f"/api/reports/assessment/{assessment_id}/json")
        assert json_report_res.status_code == 200
        assert json_report_res.json()["executive_summary"]["total_threats"] > 0

        # HTML
        html_report_res = client.get(f"/api/reports/assessment/{assessment_id}/html")
        assert html_report_res.status_code == 200
        assert "AI ThreatModel Studio" in html_report_res.text

        # XLSX
        xlsx_report_res = client.get(f"/api/reports/assessment/{assessment_id}/xlsx")
        assert xlsx_report_res.status_code == 200
        assert xlsx_report_res.headers["content-type"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        # DOCX
        docx_report_res = client.get(f"/api/reports/assessment/{assessment_id}/docx")
        assert docx_report_res.status_code == 200
        assert docx_report_res.headers["content-type"] == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def test_dashboard_metrics():
    res = client.get("/api/dashboard/metrics")
    assert res.status_code == 200
    metrics = res.json()
    assert "total_projects" in metrics
    assert "severity_breakdown" in metrics
    assert "risk_heatmap" in metrics

