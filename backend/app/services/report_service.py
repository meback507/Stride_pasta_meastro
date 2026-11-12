import os
import json
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.project import Project
from app.models.methodology import Assessment
from app.models.threat import Threat

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
except ImportError:
    openpyxl = None

try:
    import docx
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
except ImportError:
    docx = None


class ReportService:
    @staticmethod
    def get_assessment_report_data(assessment_id: int, db: Session) -> Dict[str, Any]:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            raise ValueError("Assessment not found")

        project = db.query(Project).filter(Project.id == assessment.project_id).first()
        threats = db.query(Threat).filter(Threat.assessment_id == assessment_id).all()

        threat_list = []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        for t in threats:
            ra = t.risk_assessment
            sev = ra.severity if ra else "Medium"
            if sev in severity_counts:
                severity_counts[sev] += 1

            threat_list.append({
                "id": t.id,
                "category": t.threat_category,
                "title": t.title,
                "description": t.description,
                "attack_vector": t.attack_vector or "N/A",
                "component": t.component.name if t.component else "System Wide",
                "asset": t.asset.name if t.asset else "Architecture Asset",
                "source_reference": t.source_reference or "N/A",
                "review_status": t.review_status,
                "likelihood": ra.likelihood if ra else 3,
                "impact": ra.impact if ra else 3,
                "inherent_risk": ra.inherent_risk if ra else 9,
                "residual_risk": ra.residual_risk if ra else 6,
                "severity": sev,
                "tara_feasibility": ra.tara_feasibility if ra else None,
                "tara_impact_sfop": ra.tara_impact_sfop if ra else None,
                "tara_risk_value": ra.tara_risk_value if ra else None,
                "risk_treatment": ra.risk_treatment if ra else "mitigate",
                "scenarios": [{"step": s.step_order, "desc": s.description} for s in t.scenarios],
                "mitigations": [
                    {
                        "title": m.title,
                        "description": m.description,
                        "type": m.mitigation_type,
                        "status": m.status,
                        "effort": m.implementation_effort,
                        "owner": m.owner or "Unassigned"
                    } for m in t.mitigations
                ],
                "security_requirements": [r.requirement_text for r in t.security_requirements]
            })

        return {
            "metadata": {
                "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "platform": "AI ThreatModel Studio",
                "version": "1.0",
                "assessment_id": assessment.id,
                "assessment_name": assessment.name,
                "assessment_version": assessment.version,
                "assessment_status": assessment.status
            },
            "project": {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "business_domain": project.business_domain,
                "technical_scope": project.technical_scope,
                "components": [{"name": c.name, "type": c.type, "trust_zone": c.trust_zone} for c in project.components],
                "assets": [{"name": a.name, "type": a.type, "sensitivity": a.sensitivity} for a in project.assets],
                "data_flows": [{"source": df.source_name, "target": df.target_name, "protocol": df.protocol} for df in project.data_flows]
            },
            "methodology": {
                "code": assessment.methodology.code,
                "name": assessment.methodology.name,
                "category": assessment.methodology.category,
                "description": assessment.methodology.description
            },
            "executive_summary": {
                "total_threats": len(threat_list),
                "severity_breakdown": severity_counts,
                "approved_threats": sum(1 for t in threat_list if t["review_status"] == "approved"),
                "mitigated_threats": sum(1 for t in threat_list if t["review_status"] == "mitigated"),
                "open_actions": sum(len(t["mitigations"]) for t in threat_list)
            },
            "threats": threat_list
        }

    @staticmethod
    def generate_json_report(data: Dict[str, Any], output_path: str) -> str:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return output_path

    @staticmethod
    def generate_xlsx_report(data: Dict[str, Any], output_path: str) -> str:
        if not openpyxl:
            raise RuntimeError("openpyxl is not installed")

        wb = openpyxl.Workbook()
        
        # Styles
        header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
        header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
        title_font = Font(name="Calibri", size=16, bold=True, color="1F4E78")
        bold_font = Font(name="Calibri", size=11, bold=True)
        thin_border = Border(
            left=Side(style='thin', color='D3D3D3'),
            right=Side(style='thin', color='D3D3D3'),
            top=Side(style='thin', color='D3D3D3'),
            bottom=Side(style='thin', color='D3D3D3')
        )

        # Sheet 1: Executive Summary
        ws_exec = wb.active
        ws_exec.title = "Executive Summary"
        ws_exec.views.sheetView[0].showGridLines = True

        ws_exec["A1"] = "AI ThreatModel Studio – Executive Threat Assessment"
        ws_exec["A1"].font = title_font
        ws_exec["A3"] = "Project Name:"
        ws_exec["B3"] = data["project"]["name"]
        ws_exec["A4"] = "Business Domain:"
        ws_exec["B4"] = data["project"]["business_domain"]
        ws_exec["A5"] = "Methodology:"
        ws_exec["B5"] = f"{data['methodology']['name']} ({data['methodology']['code']})"
        ws_exec["A6"] = "Assessment Status:"
        ws_exec["B6"] = data["metadata"]["assessment_status"].upper()
        ws_exec["A7"] = "Generated At:"
        ws_exec["B7"] = data["metadata"]["generated_at"]

        ws_exec["A9"] = "Risk Severity Summary"
        ws_exec["A9"].font = bold_font
        headers = ["Severity Level", "Threat Count", "Percentage"]
        for col_idx, h in enumerate(headers, 1):
            cell = ws_exec.cell(row=10, column=col_idx, value=h)
            cell.fill = header_fill
            cell.font = header_font

        total_threats = data["executive_summary"]["total_threats"] or 1
        row_idx = 11
        for sev, count in data["executive_summary"]["severity_breakdown"].items():
            ws_exec.cell(row=row_idx, column=1, value=sev).border = thin_border
            ws_exec.cell(row=row_idx, column=2, value=count).border = thin_border
            ws_exec.cell(row=row_idx, column=3, value=f"{(count / total_threats) * 100:.1f}%").border = thin_border
            row_idx += 1

        # Sheet 2: Threat Register
        ws_threats = wb.create_sheet(title="Threat Register")
        ws_threats.views.sheetView[0].showGridLines = True
        threat_headers = [
            "ID", "Category", "Threat Title", "Target Component", "Asset",
            "Likelihood (1-5)", "Impact (1-5)", "Inherent Risk", "Residual Risk",
            "Severity", "Status", "Treatment", "Attack Vector"
        ]
        for col_idx, h in enumerate(threat_headers, 1):
            cell = ws_threats.cell(row=1, column=col_idx, value=h)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center")

        for r_idx, t in enumerate(data["threats"], 2):
            ws_threats.cell(row=r_idx, column=1, value=f"THREAT-{t['id']}").border = thin_border
            ws_threats.cell(row=r_idx, column=2, value=t["category"]).border = thin_border
            ws_threats.cell(row=r_idx, column=3, value=t["title"]).border = thin_border
            ws_threats.cell(row=r_idx, column=4, value=t["component"]).border = thin_border
            ws_threats.cell(row=r_idx, column=5, value=t["asset"]).border = thin_border
            ws_threats.cell(row=r_idx, column=6, value=t["likelihood"]).border = thin_border
            ws_threats.cell(row=r_idx, column=7, value=t["impact"]).border = thin_border
            ws_threats.cell(row=r_idx, column=8, value=t["inherent_risk"]).border = thin_border
            ws_threats.cell(row=r_idx, column=9, value=t["residual_risk"]).border = thin_border
            
            sev_cell = ws_threats.cell(row=r_idx, column=10, value=t["severity"])
            sev_cell.border = thin_border
            if t["severity"] == "Critical":
                sev_cell.fill = PatternFill(start_color="FADBD8", end_color="FADBD8", fill_type="solid")
            elif t["severity"] == "High":
                sev_cell.fill = PatternFill(start_color="FDEBD0", end_color="FDEBD0", fill_type="solid")
            elif t["severity"] == "Medium":
                sev_cell.fill = PatternFill(start_color="FCF3CF", end_color="FCF3CF", fill_type="solid")
            else:
                sev_cell.fill = PatternFill(start_color="D5F5E3", end_color="D5F5E3", fill_type="solid")

            ws_threats.cell(row=r_idx, column=11, value=t["review_status"].upper()).border = thin_border
            ws_threats.cell(row=r_idx, column=12, value=t["risk_treatment"].title()).border = thin_border
            ws_threats.cell(row=r_idx, column=13, value=t["attack_vector"]).border = thin_border

        # Sheet 3: Mitigations & Requirements
        ws_mit = wb.create_sheet(title="Mitigation Plan")
        ws_mit.views.sheetView[0].showGridLines = True
        mit_headers = ["Threat ID", "Mitigation Title", "Description", "Type", "Effort", "Status", "Owner", "Derived Security Req"]
        for col_idx, h in enumerate(mit_headers, 1):
            cell = ws_mit.cell(row=1, column=col_idx, value=h)
            cell.fill = header_fill
            cell.font = header_font

        m_row = 2
        for t in data["threats"]:
            sec_reqs = " | ".join(t.get("security_requirements", []))
            for m in t["mitigations"]:
                ws_mit.cell(row=m_row, column=1, value=f"THREAT-{t['id']}").border = thin_border
                ws_mit.cell(row=m_row, column=2, value=m["title"]).border = thin_border
                ws_mit.cell(row=m_row, column=3, value=m["description"]).border = thin_border
                ws_mit.cell(row=m_row, column=4, value=m["type"]).border = thin_border
                ws_mit.cell(row=m_row, column=5, value=m["effort"]).border = thin_border
                ws_mit.cell(row=m_row, column=6, value=m["status"].title()).border = thin_border
                ws_mit.cell(row=m_row, column=7, value=m["owner"]).border = thin_border
                ws_mit.cell(row=m_row, column=8, value=sec_reqs).border = thin_border
                m_row += 1

        # Adjust column widths
        for ws in [ws_exec, ws_threats, ws_mit]:
            for col in ws.columns:
                max_len = max(len(str(cell.value or '')) for cell in col)
                col_letter = openpyxl.utils.get_column_letter(col[0].column)
                ws.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 45)

        wb.save(output_path)
        return output_path

    @staticmethod
    def generate_docx_report(data: Dict[str, Any], output_path: str) -> str:
        if not docx:
            raise RuntimeError("python-docx is not installed")

        doc = docx.Document()
        
        # Title
        p_title = doc.add_heading(level=0)
        run_title = p_title.add_run("AI ThreatModel Studio – Threat Modeling Dossier")
        run_title.font.color.rgb = RGBColor(31, 78, 120)
        run_title.font.bold = True

        doc.add_paragraph(f"Report Generated: {data['metadata']['generated_at']} | Methodology: {data['methodology']['name']}")

        # 1. Executive Summary
        h1 = doc.add_heading("1. Executive Summary", level=1)
        h1.style.font.color.rgb = RGBColor(31, 78, 120)

        p = doc.add_paragraph()
        p.add_run(f"Project: ").bold = True
        p.add_run(f"{data['project']['name']}\n")
        p.add_run(f"Domain: ").bold = True
        p.add_run(f"{data['project']['business_domain']}\n")
        p.add_run(f"Technical Scope: ").bold = True
        p.add_run(f"{data['project']['technical_scope']}\n")
        p.add_run(f"Methodology: ").bold = True
        p.add_run(f"{data['methodology']['name']} ({data['methodology']['category']})\n")

        # Summary Table
        t_summary = doc.add_table(rows=1, cols=3)
        t_summary.style = "Table Grid"
        hdr_cells = t_summary.rows[0].cells
        hdr_cells[0].text = "Severity Level"
        hdr_cells[1].text = "Identified Threats"
        hdr_cells[2].text = "Mitigation Status"
        for c in hdr_cells:
            c.paragraphs[0].runs[0].font.bold = True

        for sev, count in data["executive_summary"]["severity_breakdown"].items():
            row_cells = t_summary.add_row().cells
            row_cells[0].text = sev
            row_cells[1].text = str(count)
            row_cells[2].text = "Actions Assigned"

        # 2. System Architecture & Assets
        doc.add_heading("2. System Architecture & Asset Inventory", level=1)
        doc.add_paragraph("The threat model was evaluated against the following decomposed architecture components and critical business assets:")

        if data["project"]["components"]:
            p_comp = doc.add_paragraph()
            p_comp.add_run("Components & Trust Zones:\n").bold = True
            for c in data["project"]["components"]:
                p_comp.add_run(f"  • {c['name']} ({c['type']}) – Zone: {c['trust_zone']}\n")

        if data["project"]["assets"]:
            p_asset = doc.add_paragraph()
            p_asset.add_run("Protected Assets:\n").bold = True
            for a in data["project"]["assets"]:
                p_asset.add_run(f"  • {a['name']} ({a['type']}, Sensitivity: {a['sensitivity']})\n")

        # 3. Threat Register & Detailed Findings
        doc.add_heading("3. Structured Threat Register", level=1)
        for idx, t in enumerate(data["threats"], 1):
            doc.add_heading(f"3.{idx} [{t['category']}] {t['title']}", level=2)
            
            p_desc = doc.add_paragraph()
            p_desc.add_run("Description: ").bold = True
            p_desc.add_run(f"{t['description']}\n")
            p_desc.add_run("Attack Vector: ").bold = True
            p_desc.add_run(f"{t['attack_vector']}\n")
            p_desc.add_run("Target Component: ").bold = True
            p_desc.add_run(f"{t['component']} | Asset: {t['asset']}\n")
            p_desc.add_run("Risk Metrics: ").bold = True
            p_desc.add_run(f"Likelihood: {t['likelihood']}/5 | Impact: {t['impact']}/5 | Inherent Risk: {t['inherent_risk']}/25 | Severity: {t['severity']}\n")

            if t.get("tara_feasibility"):
                p_desc.add_run(f"ISO 21434 TARA Feasibility: {t['tara_feasibility']} | Impact (SFOP): {t['tara_impact_sfop']} | Risk Value: {t['tara_risk_value']}/5\n")

            if t["scenarios"]:
                p_scen = doc.add_paragraph()
                p_scen.add_run("Attack Scenario: ").bold = True
                for sc in t["scenarios"]:
                    p_scen.add_run(f"\n  Step {sc['step']}: {sc['desc']}")

            if t["mitigations"]:
                p_mit = doc.add_paragraph()
                p_mit.add_run("Recommended Mitigations: ").bold = True
                for m in t["mitigations"]:
                    p_mit.add_run(f"\n  • [{m['type']}] {m['title']} (Effort: {m['effort']}, Status: {m['status'].title()}) – {m['description']}")

            if t.get("security_requirements"):
                p_req = doc.add_paragraph()
                p_req.add_run("Security Requirements: ").bold = True
                for r in t["security_requirements"]:
                    p_req.add_run(f"\n  • {r}")

        doc.save(output_path)
        return output_path

    @staticmethod
    def generate_html_report(data: Dict[str, Any], output_path: str) -> str:
        """Generates a modern, printable HTML report with executive CSS styling."""
        threat_rows = ""
        for t in data["threats"]:
            badge_color = {
                "Critical": "#dc2626",
                "High": "#ea580c",
                "Medium": "#d97706",
                "Low": "#16a34a"
            }.get(t["severity"], "#4b5563")

            mits_html = "".join([f"<li><strong>[{m['type']}] {m['title']}</strong> (Effort: {m['effort']}, Status: {m['status']})<br><small>{m['description']}</small></li>" for m in t["mitigations"]])
            
            tara_html = ""
            if t.get("tara_feasibility"):
                tara_html = f"<div class='tara-box'><strong>ISO 21434:</strong> Feasibility: {t['tara_feasibility']} | SFOP: {t['tara_impact_sfop']} | Risk Value: {t['tara_risk_value']}/5</div>"

            threat_rows += f"""
            <div class="threat-card">
                <div class="threat-header">
                    <div>
                        <span class="category-pill">{t['category']}</span>
                        <h3 style="margin: 4px 0;">{t['title']}</h3>
                        <div class="meta-line">Target: <strong>{t['component']}</strong> &bull; Asset: <strong>{t['asset']}</strong> &bull; Status: <span class="status-badge">{t['review_status'].upper()}</span></div>
                    </div>
                    <div class="severity-badge" style="background-color: {badge_color};">
                        {t['severity']} ({t['inherent_risk']}/25)
                    </div>
                </div>
                <p class="threat-desc">{t['description']}</p>
                <div class="threat-vector"><strong>Attack Vector:</strong> {t['attack_vector']}</div>
                {tara_html}
                <div class="mitigation-section">
                    <strong>Mitigations & Countermeasures:</strong>
                    <ul>{mits_html or "<li>No mitigations configured.</li>"}</ul>
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI ThreatModel Studio – {data['project']['name']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 32px; background: #f8fafc; color: #1e293b; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 2px solid #0284c7; padding-bottom: 20px; margin-bottom: 28px; display: flex; justify-content: space-between; align-items: flex-start; }}
        .header h1 {{ margin: 0; color: #0f172a; font-size: 26px; }}
        .badge {{ background: #e0f2fe; color: #0369a1; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 13px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }}
        .stat-card {{ background: #f1f5f9; padding: 16px; border-radius: 8px; text-align: center; border-left: 4px solid #0284c7; }}
        .stat-card.crit {{ border-left-color: #dc2626; }}
        .stat-card.high {{ border-left-color: #ea580c; }}
        .stat-val {{ font-size: 28px; font-weight: 700; color: #0f172a; }}
        .stat-lbl {{ font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}
        .threat-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px; background: #ffffff; page-break-inside: avoid; }}
        .threat-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
        .category-pill {{ font-size: 11px; font-weight: 700; text-transform: uppercase; background: #ede9fe; color: #6d28d9; padding: 2px 8px; border-radius: 4px; }}
        .severity-badge {{ color: #ffffff; padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 13px; }}
        .meta-line {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
        .status-badge {{ background: #dcfce7; color: #15803d; padding: 2px 6px; border-radius: 4px; font-weight: 600; font-size: 11px; }}
        .threat-desc {{ font-size: 14px; line-height: 1.5; color: #334155; margin: 8px 0; }}
        .threat-vector {{ font-size: 13px; color: #475569; background: #f8fafc; padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; }}
        .tara-box {{ background: #fffbeb; border-left: 3px solid #f59e0b; padding: 8px 12px; font-size: 13px; margin-bottom: 12px; }}
        .mitigation-section {{ background: #f8fafc; padding: 12px 16px; border-radius: 6px; font-size: 13px; }}
        .mitigation-section ul {{ margin: 6px 0 0 0; padding-left: 20px; }}
        .mitigation-section li {{ margin-bottom: 6px; }}
        @media print {{ body {{ background: #fff; padding: 0; }} .container {{ box-shadow: none; border-radius: 0; padding: 0; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>{data['project']['name']}</h1>
                <p style="margin: 6px 0; color: #475569;">Business Domain: <strong>{data['project']['business_domain']}</strong> &bull; Methodology: <span class="badge">{data['methodology']['name']}</span></p>
            </div>
            <div style="text-align: right;">
                <span class="badge">{data['metadata']['platform']} {data['metadata']['version']}</span>
                <p style="margin: 6px 0; font-size: 12px; color: #64748b;">Report Date: {data['metadata']['generated_at']}</p>
            </div>
        </div>

        <h2>Executive Risk Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-val">{data['executive_summary']['total_threats']}</div>
                <div class="stat-lbl">Total Threats</div>
            </div>
            <div class="stat-card crit">
                <div class="stat-val">{data['executive_summary']['severity_breakdown']['Critical']}</div>
                <div class="stat-lbl">Critical Risk</div>
            </div>
            <div class="stat-card high">
                <div class="stat-val">{data['executive_summary']['severity_breakdown']['High']}</div>
                <div class="stat-lbl">High Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{data['executive_summary']['open_actions']}</div>
                <div class="stat-lbl">Actionable Mitigations</div>
            </div>
        </div>

        <h2>Structured Threat Register</h2>
        {threat_rows}
    </div>
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path

