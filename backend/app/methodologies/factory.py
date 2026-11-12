from typing import Dict
from app.methodologies.base import BaseMethodologyEngine
from app.methodologies.stride import StrideEngine
from app.methodologies.pasta import PastaEngine
from app.methodologies.maestro import MaestroEngine
from app.methodologies.tara import TaraEngine


class MethodologyFactory:
    _engines: Dict[str, BaseMethodologyEngine] = {
        "STRIDE": StrideEngine(),
        "PASTA": PastaEngine(),
        "MAESTRO": MaestroEngine(),
        "TARA": TaraEngine(),
        "ISO_21434": TaraEngine(),
        "ISO/SAE 21434 TARA": TaraEngine(),
    }

    @classmethod
    def get_engine(cls, code: str) -> BaseMethodologyEngine:
        normalized_code = code.strip().upper()
        if "TARA" in normalized_code or "21434" in normalized_code:
            return cls._engines["TARA"]
        
        engine = cls._engines.get(normalized_code)
        if not engine:
            # Fallback to STRIDE if unknown
            return cls._engines["STRIDE"]
        return engine

    @classmethod
    def get_all_engines(cls) -> Dict[str, BaseMethodologyEngine]:
        return {
            "STRIDE": cls._engines["STRIDE"],
            "PASTA": cls._engines["PASTA"],
            "MAESTRO": cls._engines["MAESTRO"],
            "TARA": cls._engines["TARA"]
        }
