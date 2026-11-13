import os
import io
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


def test_code_snippet_threat_modeling():
    # Sample vulnerable python snippet with SQL injection and shell execution
    sample_code = """
import os
import sqlite3

def handle_user_command(user_id, raw_cmd):
    # Unsanitized query
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    
    # Dangerous shell execution
    os.system(f"echo Log: {raw_cmd} >> audit.log")
    return cursor.fetchall()
"""
    # 1. Test Code Snippet analysis with STRIDE
    res_stride = client.post("/api/assessments/analyze-code-snippet", json={
        "code": sample_code,
        "language": "python",
        "snippet_title": "User Command Handler",
        "methodology_code": "STRIDE",
        "provider": "simulation"
    })
    assert res_stride.status_code == 200
    data_stride = res_stride.json()
    assert data_stride["status"] == "completed"
    assert data_stride["threats_generated"] > 0
    assert len(data_stride["threats"]) > 0

    categories = [t["threat_category"] for t in data_stride["threats"]]
    assert any(c in ["Tampering", "Elevation of Privilege", "Spoofing", "Information Disclosure"] for c in categories)

    # 2. Test Code Snippet analysis with MAESTRO (Agentic AI)
    agent_code = """
from langchain.agents import AgentExecutor
import requests

def agent_worker_tool(query):
    # SSRF & prompt injection vulnerable tool call
    res = requests.get(f"http://internal-api/{query}")
    return res.text
"""
    res_maestro = client.post("/api/assessments/analyze-code-snippet", json={
        "code": agent_code,
        "language": "python",
        "snippet_title": "Agentic AI Tool Worker",
        "methodology_code": "MAESTRO",
        "provider": "simulation"
    })
    assert res_maestro.status_code == 200
    data_maestro = res_maestro.json()
    assert data_maestro["threats_generated"] > 0

    # 3. Test Intelligent Auto-Detection of Methodology (Code Understanding)
    # 3a. Agentic AI snippet with AUTO -> should select MAESTRO
    res_auto_ai = client.post("/api/assessments/analyze-code-snippet", json={
        "code": agent_code,
        "language": "python",
        "snippet_title": "Intelligent Agent",
        "methodology_code": "AUTO",
        "provider": "simulation"
    })
    assert res_auto_ai.status_code == 200
    data_auto_ai = res_auto_ai.json()
    assert "MAESTRO" in data_auto_ai["methodology"]
    assert "Agentic AI" in data_auto_ai["detected_domain"]
    assert len(data_auto_ai["code_purpose_summary"]) > 0
    assert len(data_auto_ai["selected_methodology_rationale"]) > 0

    # 3b. Automotive CAN snippet with AUTO -> should select TARA
    can_code = """
void process_can_frame(uint32_t can_id, uint8_t* payload, size_t len) {
    if (can_id == 0x0120) { // Safety Critical Brake Actuation ID
        actuate_brake(payload[0]); // Unauthenticated CAN frame actuation
    }
}
"""
    res_auto_can = client.post("/api/assessments/analyze-code-snippet", json={
        "code": can_code,
        "language": "c",
        "snippet_title": "CAN Frame Receiver",
        "methodology_code": "AUTO",
        "provider": "simulation"
    })
    assert res_auto_can.status_code == 200
    data_auto_can = res_auto_can.json()
    assert "TARA" in data_auto_can["methodology"] or "21434" in data_auto_can["methodology"]
    assert "Automotive" in data_auto_can["detected_domain"]

    # 3c. Payment / financial snippet with AUTO -> should select PASTA
    payment_code = """
def process_order_payment(order_id, user_id, amount):
    # Deduct balance and update ledger
    ledger.record_transaction(order_id, amount)
    gateway.charge_card(user_id, amount)
"""
    res_auto_pay = client.post("/api/assessments/analyze-code-snippet", json={
        "code": payment_code,
        "language": "python",
        "snippet_title": "Payment Order Processor",
        "methodology_code": "AUTO",
        "provider": "simulation"
    })
    assert res_auto_pay.status_code == 200
    data_auto_pay = res_auto_pay.json()
    assert "PASTA" in data_auto_pay["methodology"]
    assert "Financial" in data_auto_pay["detected_domain"] or "Enterprise" in data_auto_pay["detected_domain"]


def test_multiple_documents_upload_and_analysis():
    # 1. Create project
    proj_res = client.post("/api/projects", json={
        "name": "Connected Autonomous Vehicle Gateway",
        "business_domain": "Automotive Telematics",
        "technical_scope": "Cellular gateway, CAN-FD boundary controller, OTA flash manager",
        "components": [
            {"name": "Telematics Control Unit", "type": "Gateway", "trust_zone": "Vehicle Boundary"},
            {"name": "Brake ECU", "type": "Actuator", "trust_zone": "Chassis CAN Network"}
        ],
        "assets": [
            {"name": "Vehicle Telemetry Stream", "type": "Data", "sensitivity": "Critical"}
        ]
    })
    assert proj_res.status_code == 201
    project = proj_res.json()
    proj_id = project["id"]

    # 2. Upload multiple architecture and requirement documents
    files = [
        ("files", ("architecture_spec.txt", io.BytesIO(b"Architecture Spec: Telematics Control Unit connects to 4G/5G and bridges to CAN-FD."), "text/plain")),
        ("files", ("security_reqs.json", io.BytesIO(b'{"requirements": ["SecOC MAC verification on CAN 0x120", "TLS 1.3 for OTA updates"]}'), "application/json")),
        ("files", ("data_flow.md", io.BytesIO(b"# Data Flow\nTelematics Unit receives remote commands and relays to Brake ECU."), "text/markdown"))
    ]
    upload_res = client.post(f"/api/documents/upload-multiple?project_id={proj_id}", files=files)
    assert upload_res.status_code == 201
    docs = upload_res.json()
    assert len(docs) == 3
    assert all(d["extracted_text"] for d in docs)
    assert any("CAN-FD" in d["extracted_text"] for d in docs)

    # 3. Create ISO/SAE 21434 TARA Assessment
    ass_res = client.post("/api/assessments", json={
        "project_id": proj_id,
        "methodology_code": "TARA",
        "name": "ISO 21434 Vehicle Threat Assessment",
        "version": "v1.0"
    })
    assert ass_res.status_code == 201
    assessment = ass_res.json()

    # 4. Run AI Threat Analysis with documents in context
    analyze_res = client.post(f"/api/assessments/{assessment['id']}/analyze", json={
        "provider": "simulation",
        "depth": "comprehensive",
        "custom_instructions": "Focus on remote cellular interfaces and CAN bus tampering"
    })
    assert analyze_res.status_code == 200
    result = analyze_res.json()
    assert result["threats_generated"] > 0
    assert "TARA" in result["methodology"] or "21434" in result["methodology"]



