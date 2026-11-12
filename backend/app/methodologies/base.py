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
