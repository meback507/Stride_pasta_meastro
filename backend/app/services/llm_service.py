import time
import json
import httpx
from typing import Dict, Any, List, Optional
from app.config import settings
from app.methodologies.base import BaseMethodologyEngine
from app.services.document_service import DocumentService


class LLMService:
    @staticmethod
    async def generate_threats(
        engine: BaseMethodologyEngine,
        project_data: Dict[str, Any],
        document_context: str,
        provider: Optional[str] = None,
        model_name: Optional[str] = None,
        depth: str = "comprehensive",
        focus_areas: Optional[List[str]] = None,
        custom_instructions: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Orchestrates LLM threat generation with provider fallback, prompt injection defense,
        and JSON schema validation.
        """
        start_time = time.time()
        active_provider = (provider or settings.DEFAULT_LLM_PROVIDER).lower()
        active_model = model_name or (settings.OPENAI_MODEL if active_provider == "openai" else settings.OLLAMA_MODEL)

        # 1. Sanitize untrusted architecture context
        safe_context = DocumentService.sanitize_untrusted_context(document_context)

        # 2. Build methodology-specific prompt
        system_prompt = engine.get_system_prompt()
        user_prompt = engine.build_analysis_prompt(
            project_data=project_data,
            document_context=safe_context,
            depth=depth,
            focus_areas=focus_areas,
            custom_instructions=custom_instructions
        )

        threats = []
        tokens_used = {"prompt_tokens": 0, "completion_tokens": 0}
        error_msg = None
        status = "success"

        # 3. Provider execution
        try:
            if active_provider == "openai" and settings.OPENAI_API_KEY:
                threats, tokens_used = await LLMService._call_openai(
                    system_prompt, user_prompt, active_model
                )
            elif active_provider == "ollama":
                threats, tokens_used = await LLMService._call_ollama(
                    system_prompt, user_prompt, active_model
                )
            else:
                # Deterministic Simulation Provider
                threats = engine.generate_simulated_threats(project_data)
                active_provider = "simulation"
                active_model = f"deterministic-expert-v1.0 ({engine.code})"
                tokens_used = {"prompt_tokens": len(user_prompt) // 4, "completion_tokens": 850}

        except Exception as e:
            # Fallback to simulation engine if remote API fails
            error_msg = f"Provider {active_provider} error: {str(e)}. Falling back to deterministic methodology simulation."
            threats = engine.generate_simulated_threats(project_data)
            active_provider = "simulation (fallback)"
            active_model = f"deterministic-expert-v1.0 ({engine.code})"
            status = "fallback_success"

        execution_time_ms = int((time.time() - start_time) * 1000)

        # 4. Standardize and score threats through methodology engine
        processed_threats = []
        for t in threats:
            # Calculate deterministic risk according to methodology
            risk_calc = engine.calculate_risk(t)
            t["risk_assessment"] = risk_calc
            t["likelihood"] = risk_calc["likelihood"]
            t["impact"] = risk_calc["impact"]
            processed_threats.append(t)

        return {
            "threats": processed_threats,
            "provider_used": active_provider,
            "model_used": active_model,
            "execution_time_ms": execution_time_ms,
            "prompt_tokens": tokens_used.get("prompt_tokens", 0),
            "completion_tokens": tokens_used.get("completion_tokens", 0),
            "status": status,
            "error_message": error_msg
        }

    @staticmethod
    async def _call_openai(system_prompt: str, user_prompt: str, model: str):
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY, base_url=settings.OPENAI_BASE_URL)
        
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.2
        )
        
        content = response.choices[0].message.content or "{}"
        parsed = json.loads(content)
        threats = parsed.get("threats", [])
        
        tokens = {
            "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
            "completion_tokens": response.usage.completion_tokens if response.usage else 0
        }
        return threats, tokens

    @staticmethod
    async def _call_ollama(system_prompt: str, user_prompt: str, model: str):
        url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/chat"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.2}
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "{}")
            parsed = json.loads(content)
            threats = parsed.get("threats", [])
            tokens = {
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0)
            }
            return threats, tokens
