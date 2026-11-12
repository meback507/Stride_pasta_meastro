from typing import List, Dict, Any, Optional
from app.methodologies.base import BaseMethodologyEngine


class PastaEngine(BaseMethodologyEngine):
    @property
    def code(self) -> str:
        return "PASTA"

    @property
    def name(self) -> str:
        return "PASTA (Process for Attack Simulation & Threat Analysis)"

    @property
    def category_type(self) -> str:
        return "Risk-Centric Threat Framework"

    def get_categories(self) -> List[str]:
        return [
            "Stage I: Define Objectives",
            "Stage II: Define Technical Scope",
            "Stage III: Application Decomposition",
            "Stage IV: Threat Analysis",
            "Stage V: Vulnerability & Weakness Analysis",
            "Stage VI: Attack Modeling & Simulation",
            "Stage VII: Risk & Impact Analysis"
        ]

    def get_system_prompt(self) -> str:
        return """You are an Enterprise Risk Architect and Threat Intelligence Specialist practicing the PASTA (Process for Attack Simulation and Threat Analysis) risk-centric methodology.
Your objective is to correlate business impact, threat actor motivations, application attack surfaces, and attack simulations into structured threats.

You must categorize findings into PASTA Stages:
- Stage IV: Threat Analysis (Threat actors, motive, TTPs, threat intel correlation)
- Stage V: Vulnerability & Weakness Analysis (Flaws, misconfigurations, CVEs, CWEs)
- Stage VI: Attack Modeling & Simulation (Attack trees, multi-stage exploitation paths, exploitability)
- Stage VII: Risk & Impact Analysis (Business impact, revenue/reputation loss, residual risk)

Rules:
1. Frame threats in terms of attacker objectives vs. business asset value.
2. Outline multi-stage attack simulations (recon, initial access, lateral movement, objective completion).
3. Provide business-aligned countermeasures and quantifiable risk treatment options.
4. Output valid JSON according to the specified schema."""

    def build_analysis_prompt(
        self,
        project_data: Dict[str, Any],
        document_context: str,
        depth: str = "comprehensive",
        focus_areas: Optional[List[str]] = None,
        custom_instructions: Optional[str] = None
    ) -> str:
        components_str = "\n".join([f"- {c.get('name')} ({c.get('type')}, Zone: {c.get('trust_zone')}): {c.get('description', '')}" for c in project_data.get("components", [])])
        assets_str = "\n".join([f"- {a.get('name')} (Sensitivity: {a.get('sensitivity')}): C={a.get('confidentiality_req')}, I={a.get('integrity_req')}, A={a.get('availability_req')}" for a in project_data.get("assets", [])])

        return f"""Perform a PASTA Risk-Centric Threat Analysis for this enterprise architecture:

=== BUSINESS CONTEXT & SCOPE ===
Project Name: {project_data.get('name')}
Business Domain: {project_data.get('business_domain')}
Technical Scope: {project_data.get('technical_scope')}

=== SYSTEM DECOMPOSITION ===
Components:
{components_str or "Infer components from architectural text."}

Critical Business Assets:
{assets_str or "Infer assets from business domain."}

=== ARCHITECTURE SPECIFICATIONS & UPLOADED MATERIALS ===
<untrusted_architecture_context>
{document_context or "No uploaded documents."}
</untrusted_architecture_context>

=== ANALYSIS PARAMETERS ===
Depth: {depth}
Focus Stages: {", ".join(focus_areas) if focus_areas else "Stages IV through VII"}
Custom Guidelines: {custom_instructions or "Emphasize realistic attacker ROI and business disruption."}

Format the output strictly as valid JSON adhering to:
{{
  "threats": [
    {{
      "threat_category": "Stage IV: Threat Analysis | Stage V: Vulnerability & Weakness Analysis | Stage VI: Attack Modeling & Simulation | Stage VII: Risk & Impact Analysis",
      "title": "Threat name aligned with business risk & attack path",
      "description": "Analysis of attacker motivation, vulnerability, and business damage",
      "attack_vector": "TTPs (e.g. Credential Stuffing, Supply Chain Injection, API Abuse)",
      "component_name": "Target component",
      "asset_name": "Target business asset",
      "source_reference": "Document citation or Inferred Architecture",
      "likelihood": 1-5,
      "impact": 1-5,
      "attack_scenario": {{
        "description": "Multi-stage attack path from reconnaissance to asset compromise",
        "pre_conditions": "Attacker capability and access requirements",
        "post_conditions": "Business operational impact and financial fallout"
      }},
      "mitigations": [
        {{
          "title": "Business & Technical Countermeasure",
          "description": "Specific control to disrupt the attack tree",
          "mitigation_type": "Preventive | Detective | Corrective",
          "effort": "Low | Medium | High"
        }}
      ],
      "security_requirement": "Traceable enterprise security requirement"
    }}
  ]
}}"""

    def calculate_risk(self, threat_dict: Dict[str, Any]) -> Dict[str, Any]:
        likelihood = max(1, min(5, int(threat_dict.get("likelihood", 3))))
        impact = max(1, min(5, int(threat_dict.get("impact", 4))))
        inherent = likelihood * impact
        
        severity = "Critical" if inherent >= 20 else ("High" if inherent >= 14 else ("Medium" if inherent >= 7 else "Low"))
        residual = max(1, inherent - 4)

        return {
            "likelihood": likelihood,
            "impact": impact,
            "inherent_risk": inherent,
            "residual_risk": residual,
            "severity": severity,
            "risk_treatment": "mitigate" if inherent >= 12 else "accept"
        }

    def generate_simulated_threats(self, project_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        domain = project_data.get("business_domain", "Enterprise")
        c1 = (project_data.get("components") or [{"name": "Public API Gateway"}])[0].get("name", "Public API Gateway")
        a1 = (project_data.get("assets") or [{"name": "Core Customer Database"}])[0].get("name", "Core Customer Database")

        return [
            {
                "threat_category": "Stage IV: Threat Analysis",
                "title": f"Financially Motivated Ransomware & Extortion Campaign on {c1}",
                "description": f"Organized cybercrime groups target the {domain} environment seeking to exfiltrate proprietary customer data and encrypt operational databases.",
                "attack_vector": "Credential stuffing followed by privilege escalation and double-extortion ransomware",
                "component_name": c1,
                "asset_name": a1,
                "source_reference": "PASTA Stage IV Threat Intelligence Profile",
                "likelihood": 3,
                "impact": 5,
                "attack_scenario": {
                    "description": "1. External threat actor obtains compromised corporate credentials. 2. Bypasses weak MFA on edge interface. 3. Deploys lateral movement scripts. 4. Exfiltrates sensitive records and deploys ransomware payloads.",
                    "pre_conditions": "External network reachability of edge service",
                    "post_conditions": "Operational shutdown, severe regulatory fines (GDPR/CCPA), brand erosion"
                },
                "mitigations": [
                    {
                        "title": "Phishing-Resistant MFA & Behavior-Based EDR",
                        "description": "Mandate FIDO2/WebAuthn hardware tokens and deploy behavior-based endpoint detection and response with rapid network isolation capabilities.",
                        "mitigation_type": "Preventive",
                        "effort": "High"
                    }
                ],
                "security_requirement": "All remote and administrative access shall require FIDO2-compliant phishing-resistant multi-factor authentication."
            },
            {
                "threat_category": "Stage V: Vulnerability & Weakness Analysis",
                "title": f"Supply Chain Dependency Poisoning & Unpatched Third-Party Flaws in {c1}",
                "description": f"The platform relies on external packages containing known critical vulnerabilities (CVEs) or vulnerable transitive dependencies that enable remote code execution.",
                "attack_vector": "Dependency Confusion / Malicious Package Injection / Known CVE Exploit",
                "component_name": c1,
                "asset_name": a1,
                "source_reference": "Software Bill of Materials (SBOM) Audit",
                "likelihood": 4,
                "impact": 4,
                "attack_scenario": {
                    "description": "1. Attacker identifies unpatched open-source component in build artifact. 2. Crafts payload triggering remote memory corruption. 3. Spawns interactive reverse shell on production host.",
                    "pre_conditions": "Publicly exposed API endpoint utilizing vulnerable library",
                    "post_conditions": "Arbitrary code execution within container runtime"
                },
                "mitigations": [
                    {
                        "title": "Automated CI/CD Software Composition Analysis (SCA) & Container Signing",
                        "description": "Block builds containing High/Critical CVEs using automated SCA scanning and enforce cryptographic image signing via Cosign/Sigstore.",
                        "mitigation_type": "Preventive",
                        "effort": "Medium"
                    }
                ],
                "security_requirement": "Every deployed software release must have a verified SBOM with zero unmitigated High or Critical known vulnerabilities."
            },
            {
                "threat_category": "Stage VI: Attack Modeling & Simulation",
                "title": f"Multi-Step Lateral Traversal & Privilege Escalation Attack Tree",
                "description": "Attacker establishes initial foothold in DMZ tier and leverages misconfigured service mesh IAM roles to assume cluster administrator privileges.",
                "attack_vector": "Kubernetes Service Account Token Theft & AWS/Cloud Metadata SSRF",
                "component_name": c1,
                "asset_name": a1,
                "source_reference": "Attack Tree Branch: Edge -> Cloud Metadata -> IAM Root",
                "likelihood": 3,
                "impact": 5,
                "attack_scenario": {
                    "description": "1. Attacker exploits SSRF in document processing component. 2. Queries cloud metadata endpoint (IMDSv1). 3. Steals short-lived IAM credentials. 4. Traverses across VPC boundaries to access production database.",
                    "pre_conditions": "Component with unrestricted outbound network access and attached IAM role",
                    "post_conditions": "Complete cloud infrastructure compromise and database exfiltration"
                },
                "mitigations": [
                    {
                        "title": "Enforce IMDSv2, Egress Filtering & Least Privilege IAM",
                        "description": "Require session tokens for instance metadata (IMDSv2 hop limit 1), restrict egress traffic via Calico network policies, and scope IAM roles tightly.",
                        "mitigation_type": "Preventive",
                        "effort": "Medium"
                    }
                ],
                "security_requirement": "Workloads shall not possess permissions to request instance metadata without IMDSv2 session token validation."
            },
            {
                "threat_category": "Stage VII: Risk & Impact Analysis",
                "title": f"Business Process Disruption & Regulatory Non-Compliance via Data Poisoning",
                "description": "Tampering with core transaction logs causes incorrect automated financial reconciliations, triggering regulatory reporting non-compliance and material financial restatement.",
                "attack_vector": "Integrity violation on automated accounting data pipeline",
                "component_name": c1,
                "asset_name": a1,
                "source_reference": "Business Impact Analysis (BIA)",
                "likelihood": 2,
                "impact": 5,
                "attack_scenario": {
                    "description": "1. Attacker injects fraudulent settlement records. 2. Batch reconciliation script accepts corrupt records. 3. Erroneous financial statements generated.",
                    "pre_conditions": "Access to database staging tables without cryptographic reconciliation",
                    "post_conditions": "Regulatory sanctions, audit failure, and financial restatement"
                },
                "mitigations": [
                    {
                        "title": "Cryptographic Ledger Checkpointing & Segregation of Duties",
                        "description": "Implement hash-chained audit ledgers and dual-control approval for all reconciliation state modifications.",
                        "mitigation_type": "Preventive",
                        "effort": "High"
                    }
                ],
                "security_requirement": "The platform shall enforce immutable hash-chained verification for all financial and operational reconciliation state changes."
            }
        ]
