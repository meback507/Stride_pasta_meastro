from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class BaseMethodologyEngine(ABC):
    """Abstract Base Class for all Threat Modeling Methodologies."""

    @property
    @abstractmethod
    def code(self) -> str:
        """Returns the unique code of the methodology: STRIDE, PASTA, MAESTRO, TARA."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Full human-readable name of the methodology."""
        pass

    @property
    @abstractmethod
    def category_type(self) -> str:
        """Type: 'Technical Methodology', 'Risk-Centric Framework', 'AI Framework', or 'Automotive Standard'."""
        pass

    @abstractmethod
    def get_categories(self) -> List[str]:
        """Returns the categories, layers, or stages for this methodology."""
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Returns the methodology-specific expert system prompt for LLM analysis."""
        pass

    @abstractmethod
    def build_analysis_prompt(
        self,
        project_data: Dict[str, Any],
        document_context: str,
        depth: str = "comprehensive",
        focus_areas: Optional[List[str]] = None,
        custom_instructions: Optional[str] = None
    ) -> str:
        """Generates the prompt provided to the LLM to analyze the architecture."""
        pass

    @abstractmethod
    def calculate_risk(self, threat_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Performs deterministic risk calculations according to methodology rules."""
        pass

    @abstractmethod
    def generate_simulated_threats(self, project_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generates realistic, methodology-conforming threats deterministically.
        Used when running in offline simulation mode or as fallback.
        """
        pass

    def build_code_snippet_prompt(
        self,
        code_snippet: str,
        language: str = "auto",
        snippet_title: str = "Pasted Code",
        custom_instructions: Optional[str] = None
    ) -> str:
        """Generates prompt for performing threat modeling on a pasted code snippet."""
        return f"""Perform a code-level threat model using the {self.name} ({self.code}) methodology on the following code snippet.

Snippet Title: {snippet_title}
Language: {language}
Additional Instructions: {custom_instructions or "Identify code vulnerabilities, missing checks, privilege escalations, and attack surfaces."}

=== CODE SNIPPET ===
```{language}
{code_snippet}
```

Identify all threats adhering strictly to the {self.code} methodology categories: {", ".join(self.get_categories())}.
For each threat, cite specific line numbers or functions in the snippet, explain the attack vector, assess likelihood and impact (1-5), and provide code-level remediation guidance with code examples.

Output JSON:
{{
  "threats": [
    {{
      "threat_category": "{self.get_categories()[0]}",
      "title": "Threat Title (Code-Level)",
      "description": "Specific code vulnerability and impact",
      "attack_vector": "How attacker exploits this code construct",
      "component_name": "{snippet_title}",
      "asset_name": "Target code asset/data",
      "source_reference": "Code Snippet lines X-Y",
      "likelihood": 1-5,
      "impact": 1-5,
      "attack_scenario": {{
        "description": "Step-by-step exploit against this code snippet",
        "pre_conditions": "Attacker prerequisites",
        "post_conditions": "Compromise state"
      }},
      "mitigations": [
        {{
          "title": "Code Remediation",
          "description": "How to refactor or sanitize this code",
          "mitigation_type": "Preventive",
          "effort": "Low | Medium"
        }}
      ],
      "security_requirement": "Code security requirement"
    }}
  ]
}}"""

    def generate_simulated_code_threats(
        self,
        code_snippet: str,
        language: str = "auto",
        snippet_title: str = "Code Snippet"
    ) -> List[Dict[str, Any]]:
        """Fallback simulation for code snippet threat modeling."""
        return self.generate_simulated_threats({"name": snippet_title, "components": [{"name": snippet_title}]})


