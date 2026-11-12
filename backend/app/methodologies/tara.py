from typing import List, Dict, Any, Optional
from app.methodologies.base import BaseMethodologyEngine


class TaraEngine(BaseMethodologyEngine):
    @property
    def code(self) -> str:
        return "TARA"

    @property
    def name(self) -> str:
        return "ISO/SAE 21434 TARA (Automotive Cybersecurity)"

    @property
    def category_type(self) -> str:
        return "Automotive Engineering Standard"

    def get_categories(self) -> List[str]:
        return [
            "Item Definition & Boundary",
            "Asset & Cybersecurity Property (C-I-A)",
            "Damage Scenario (SFOP)",
            "Threat Scenario",
            "Attack Path & Feasibility",
            "Risk Determination (1-5)",
            "Cybersecurity Goals & Claims"
        ]

    def get_system_prompt(self) -> str:
        return """You are a Principal Automotive Cybersecurity Engineer and Lead TARA Assessor certified in ISO/SAE 21434.
Your responsibility is to analyze automotive Items (ECUs, Telematics, Gateways, ADAS, IVI, In-Vehicle Networks like CAN/Ethernet) and produce formal Threat Analysis and Risk Assessments (TARA).

You must adhere to ISO/SAE 21434 requirements:
1. Identify Assets and their affected Cybersecurity Properties (Confidentiality, Integrity, Availability).
2. Formulate Damage Scenarios evaluating impact across all four SFOP dimensions:
   - Safety (Negligible, Moderate, Major, Severe)
   - Financial (Negligible, Moderate, Major, Severe)
   - Operational (Negligible, Moderate, Major, Severe)
   - Privacy (Negligible, Moderate, Major, Severe)
3. Formulate Threat Scenarios and Attack Paths.
4. Estimate Attack Feasibility (High, Medium, Low, Very Low) based on Elapsed Time, Specialist Expertise, Knowledge of Item, Window of Opportunity, and Equipment.
5. Determine Cybersecurity Risk Value on the ISO 21434 1 to 5 scale.
6. Specify derived Cybersecurity Goals (CG) and Cybersecurity Claims (CC).

Rules:
1. Distinguish physical, adjacent (BLE/WiFi), and remote (Cellular/Cloud) attack vectors.
2. Focus on vehicular safety and functional degradation.
3. Output valid JSON strictly conforming to the schema."""

    def build_analysis_prompt(
        self,
        project_data: Dict[str, Any],
        document_context: str,
        depth: str = "comprehensive",
        focus_areas: Optional[List[str]] = None,
        custom_instructions: Optional[str] = None
    ) -> str:
        components_str = "\n".join([f"- {c.get('name')} ({c.get('type')}, Trust Zone: {c.get('trust_zone')}): {c.get('description', '')}" for c in project_data.get("components", [])])
        assets_str = "\n".join([f"- {a.get('name')} (Type: {a.get('type')}): C={a.get('confidentiality_req')}, I={a.get('integrity_req')}, A={a.get('availability_req')}" for a in project_data.get("assets", [])])
        flows_str = "\n".join([f"- {df.get('source_name')} -> {df.get('target_name')} via {df.get('protocol')}" for df in project_data.get("data_flows", [])])

        return f"""Perform an ISO/SAE 21434 Automotive TARA analysis for this vehicle item/subsystem:

=== ITEM DEFINITION & OPERATIONAL ENVIRONMENT ===
Item Name: {project_data.get('name')}
Vehicle Domain: {project_data.get('business_domain')}
Functional Scope: {project_data.get('technical_scope')}

=== AUTOMOTIVE HARDWARE/SOFTWARE COMPONENTS & ECUS ===
{components_str or "Infer vehicle ECUs, gateway, sensors, and telematics from context."}

=== VEHICLE ASSETS & SENSITIVE SIGNALS ===
{assets_str or "Infer vehicle assets (e.g. Steering/Braking actuation commands, Cryptographic Keys, Firmware)."}

=== IN-VEHICLE NETWORKS & EXTERNAL INTERFACES (CAN, LIN, Automotive Ethernet, Cellular, BLE, OBD-II) ===
{flows_str or "No explicit vehicle bus interfaces provided; infer standard vehicle topologies."}

=== UPLOADED ITEM DEFINITION & VEHICLE ARCHITECTURE DOCS ===
<untrusted_architecture_context>
{document_context or "No uploaded vehicle engineering documents."}
</untrusted_architecture_context>

=== TARA PARAMETERS ===
Depth: {depth}
Focus Areas: {", ".join(focus_areas) if focus_areas else "Safety-critical actuation and remote vehicle interfaces"}
Instructions: {custom_instructions or "Evaluate remote telematics pivot to safety CAN bus."}

Generate structured TARA findings strictly in valid JSON adhering to:
{{
  "threats": [
    {{
      "threat_category": "Damage Scenario (SFOP) | Threat Scenario | Attack Path & Feasibility",
      "title": "ISO 21434 Threat Title (e.g. Remote CAN Injection leading to Loss of Braking)",
      "description": "Comprehensive explanation of threat scenario, asset affected, and failure mode",
      "attack_vector": "Remote Cellular -> Telematics -> Gateway -> Powertrain/Chassis CAN bus",
      "component_name": "Target ECU / Vehicle Component",
      "asset_name": "Target Vehicle Asset",
      "source_reference": "Vehicle Item Definition Section",
      "tara_feasibility": "High | Medium | Low | Very Low",
      "tara_impact_sfop": "S:Severe, F:Major, O:Major, P:Moderate",
      "likelihood": 1-5,
      "impact": 1-5,
      "attack_scenario": {{
        "description": "Sequential steps taken by attacker from entry interface to vehicle actuation compromise",
        "pre_conditions": "Attacker prerequisites (e.g. Remote cellular exploit or physical OBD-II access)",
        "post_conditions": "Vehicle dynamic hazard or safety impairment"
      }},
      "mitigations": [
        {{
          "title": "Cybersecurity Goal (CG) / In-Vehicle Defense",
          "description": "SecOC (Secure Onboard Communication), Hardware Security Module (HSM), or Gateway Filtering",
          "mitigation_type": "Preventive | Detective",
          "effort": "Medium | High"
        }}
      ],
      "security_requirement": "Formal ISO/SAE 21434 Cybersecurity Goal (e.g. [CG-01] Ensure authenticity of braking actuation signals)"
    }}
  ]
}}"""

    def calculate_risk(self, threat_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates ISO/SAE 21434 Risk Value (1 to 5) based on Feasibility vs SFOP Impact.
        """
        feasibility = threat_dict.get("tara_feasibility", "Medium")
        sfop = threat_dict.get("tara_impact_sfop", "S:Major, F:Moderate, O:Moderate, P:Low")
        
        # Determine highest impact level from SFOP
        if "Severe" in sfop:
            impact_score = 5
        elif "Major" in sfop:
            impact_score = 4
        elif "Moderate" in sfop:
            impact_score = 3
        else:
            impact_score = 1

        feasibility_map = {"High": 4, "Medium": 3, "Low": 2, "Very Low": 1}
        feasibility_score = feasibility_map.get(feasibility, 3)

        # ISO 21434 Risk Matrix derivation:
        # High Feasibility + Severe Impact = Risk Value 5
        # Low Feasibility + Negligible Impact = Risk Value 1
        matrix_val = (feasibility_score * impact_score) // 4
        risk_value = max(1, min(5, matrix_val))

        severity_map = {1: "Low", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
        severity = severity_map.get(risk_value, "Medium")

        return {
            "likelihood": feasibility_score,
            "impact": impact_score,
            "inherent_risk": feasibility_score * impact_score,
            "residual_risk": max(1, (feasibility_score * impact_score) - 4),
            "severity": severity,
            "tara_feasibility": feasibility,
            "tara_impact_sfop": sfop,
            "tara_risk_value": risk_value,
            "risk_treatment": "mitigate" if risk_value >= 3 else "accept"
        }

    def generate_simulated_threats(self, project_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        c1 = (project_data.get("components") or [{"name": "Telematics Control Unit (TCU)"}])[0].get("name", "Telematics Control Unit (TCU)")
        a1 = (project_data.get("assets") or [{"name": "Powertrain CAN Bus Actuation Commands"}])[0].get("name", "Powertrain CAN Bus Actuation Commands")

        return [
            {
                "threat_category": "Threat Scenario",
                "title": f"Remote Code Execution on {c1} via Cellular Air Interface",
                "description": "Vulnerabilities in the cellular modem firmware or MQTT telematics stack allow a remote adversary to achieve root shell execution on the TCU without physical vehicle access.",
                "attack_vector": "Over-the-Air Cellular Baseband Buffer Overflow / Protocol Exploit",
                "component_name": c1,
                "asset_name": a1,
                "source_reference": "ISO 21434 Item Definition: Telematics & Remote Services",
                "tara_feasibility": "Medium",
                "tara_impact_sfop": "S:Severe, F:Major, O:Major, P:Severe",
                "likelihood": 3,
                "impact": 5,
                "attack_scenario": {
                    "description": "1. Attacker exploits unauthenticated telematics message parsing flaw over 4G/5G. 2. Gains shell on TCU application processor. 3. Exploits kernel privilege escalation to reach gateway interface.",
                    "pre_conditions": "Public cellular network connectivity to vehicle VIN / eSIM IP",
                    "post_conditions": "Remote unauthorized code execution on vehicle edge node"
                },
                "mitigations": [
                    {
                        "title": "Hardware Security Module (HSM) & Secure Boot",
                        "description": "Enforce cryptographic secure boot with hardware root-of-trust in HSM and isolate telematics runtime using ARM TrustZone or seL4 microkernel.",
                        "mitigation_type": "Preventive",
                        "effort": "High"
                    }
                ],
                "security_requirement": "[CG-TCU-01] The Telematics Control Unit shall verify digital signatures of all executable code using an immutable hardware root of trust before execution."
            },
            {
                "threat_category": "Attack Path & Feasibility",
                "title": f"Lateral Pivot from Infotainment/TCU to Safety CAN Bus via Central Gateway",
                "description": "Insufficient domain segregation or routing filter misconfigurations in the Central Gateway ECU permit arbitrary CAN frame injection onto the safety-critical chassis bus.",
                "attack_vector": "CAN ID Spoofing across Central Gateway boundary",
                "component_name": "Central Gateway ECU",
                "asset_name": a1,
                "source_reference": "In-Vehicle Network Topology & Filtering Rules",
                "tara_feasibility": "Medium",
                "tara_impact_sfop": "S:Severe, F:Major, O:Major, P:Low",
                "likelihood": 3,
                "impact": 5,
                "attack_scenario": {
                    "description": "1. Attacker pivots from compromised TCU. 2. Sends crafted CAN frames with spoofed Steering/Brake arbitration IDs. 3. Gateway forwards frame without cryptographic authentication. 4. Braking ECU executes unintended actuation.",
                    "pre_conditions": "Compromised node connected to vehicle gateway",
                    "post_conditions": "Unintended vehicle acceleration or loss of braking control while in motion"
                },
                "mitigations": [
                    {
                        "title": "AUTOSAR Secure Onboard Communication (SecOC) & CAN IDS",
                        "description": "Implement SecOC with freshness values and MAC verification for all safety-relevant CAN-FD messages, coupled with CAN-bus Intrusion Detection Systems (IDS).",
                        "mitigation_type": "Preventive",
                        "effort": "High"
                    }
                ],
                "security_requirement": "[CG-NET-02] All safety-relevant CAN-FD and Ethernet frames transmitted across domain boundaries shall be authenticated using SecOC with cryptographic freshness."
            },
            {
                "threat_category": "Damage Scenario (SFOP)",
                "title": "Malicious Firmware Flashing via Diagnostic OBD-II Interface",
                "description": "An attacker connected to the physical OBD-II diagnostic port bypasses SecurityAccess (UDS Service 0x27) to flash unauthorized modified calibration files or malicious firmware into vehicle ECUs.",
                "attack_vector": "Physical OBD-II Port / UDS Diagnostic Protocol Exploit",
                "component_name": "Engine Control Unit (ECU)",
                "asset_name": "ECU Firmware & Calibration Maps",
                "source_reference": "ISO 14229 UDS Specification & Diagnostic Firewall",
                "tara_feasibility": "High",
                "tara_impact_sfop": "S:Major, F:Major, O:Severe, P:Negligible",
                "likelihood": 4,
                "impact": 4,
                "attack_scenario": {
                    "description": "1. Attacker connects hardware dongle to OBD-II port. 2. Uses static or brute-forced Seed-Key algorithm for UDS Service 0x27. 3. Overwrites ECU flash memory with tampered firmware.",
                    "pre_conditions": "Physical access to vehicle cabin OBD-II port",
                    "post_conditions": "Permanent ECU backdoor, emission defeat, or disabled safety interlocks"
                },
                "mitigations": [
                    {
                        "title": "Asymmetric Diagnostic Authentication & OBD-II Firewall",
                        "description": "Enforce ISO 13400-2 DoIP with TLS and asymmetric certificate-based authentication for diagnostic services (zero static seed-key algorithms).",
                        "mitigation_type": "Preventive",
                        "effort": "Medium"
                    }
                ],
                "security_requirement": "[CG-DIAG-03] Diagnostic services granting flashing or calibration capabilities shall require mutual asymmetric cryptographic authentication."
            },
            {
                "threat_category": "Damage Scenario (SFOP)",
                "title": "Eavesdropping and Relay Attack on Passive Keyless Entry (PKE) BLE Interface",
                "description": "Adversaries employ wireless signal relay transceivers or Bluetooth Low Energy (BLE) spoofing to trick the vehicle into unlocking and enabling vehicle ignition without owner proximity.",
                "attack_vector": "Sub-GHz / BLE Radio Frequency Relay Attack",
                "component_name": "Body Control Module (BCM)",
                "asset_name": "Vehicle Entry & Ignition Authorization Tokens",
                "source_reference": "Wireless Access & Smart Key System Spec",
                "tara_feasibility": "High",
                "tara_impact_sfop": "S:Low, F:Severe, O:Major, P:Severe",
                "likelihood": 4,
                "impact": 4,
                "attack_scenario": {
                    "description": "1. Attacker A stands near owner holding key fob. 2. Attacker B stands next to vehicle. 3. Relay hardware bridges RF communication within milliseconds. 4. Vehicle unlocks and drives away.",
                    "pre_conditions": "Owner key fob within 10-20 meters of attacker transceiver",
                    "post_conditions": "Physical vehicle theft and unauthorized unauthorized driving"
                },
                "mitigations": [
                    {
                        "title": "Ultra-Wideband (UWB) Time-of-Flight (ToF) Distance Bounding",
                        "description": "Replace or augment BLE with Ultra-Wideband (UWB) physical layer distance bounding to verify true physical proximity via speed-of-light measurements.",
                        "mitigation_type": "Preventive",
                        "effort": "High"
                    }
                ],
                "security_requirement": "[CG-ACCESS-04] The keyless entry and start system shall enforce cryptographic distance bounding resistant to RF relay amplification."
            }
        ]

