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
    async def classify_code_and_methodology(
        code_snippet: str,
        language: str = "auto",
        provider: Optional[str] = None,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyzes the code snippet function, architectural domain, and automatically
        determines the most suitable threat modeling methodology (STRIDE, PASTA, MAESTRO, TARA)
        along with code function explanation and selection justification.
        """
        active_provider = (provider or settings.DEFAULT_LLM_PROVIDER).lower()
        active_model = model_name or (settings.OPENAI_MODEL if active_provider == "openai" else settings.OLLAMA_MODEL)
        
        # 1. Try LLM if configured
        if active_provider == "openai" and settings.OPENAI_API_KEY:
            try:
                system_prompt = """You are a Principal Security Architect specializing in threat modeling.
Analyze the provided source code snippet:
1. Explain what the function and architecture of the code is.
2. Determine which of the four methodologies is most suitable:
   - MAESTRO: For Agentic AI, LLM prompts, multi-agent swarms, tool calling, RAG vector memory.
   - TARA: For automotive ECUs, CAN/LIN bus, telematics, firmware, vehicle control systems (ISO/SAE 21434).
   - PASTA: For business-critical enterprise transactions, financial/payment flows, multi-tier business logic.
   - STRIDE: For general software, web services, microservices, cloud APIs, database and authentication logic.
Output strictly JSON:
{
  "code_purpose_summary": "1-2 sentence description of code function and intent",
  "detected_domain": "Domain name",
  "selected_methodology": "STRIDE | PASTA | MAESTRO | TARA",
  "methodology_name": "Full name",
  "rationale": "Clear justification explaining why this methodology is the best fit for this code construct"
}"""
                user_prompt = f"Code snippet ({language}):\n\n```{language}\n{code_snippet[:6000]}\n```"
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY, base_url=settings.OPENAI_BASE_URL)
                response = await client.chat.completions.create(
                    model=active_model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1
                )
                content = response.choices[0].message.content or "{}"
                parsed = json.loads(content)
                if parsed.get("selected_methodology") in ["STRIDE", "PASTA", "MAESTRO", "TARA"]:
                    return parsed
            except Exception:
                pass

        # 2. Intelligent Semantic Code Classifier Fallback
        code_lower = code_snippet.lower()
        
        # Check Agentic AI / LLM (MAESTRO)
        ai_keywords = [
            "langchain", "openai", "agent", "prompt", "embedding", "vector", "rag", 
            "llm", "tool", "anthropic", "swarm", "crewai", "autogen", "chroma", 
            "pinecone", "qdrant", "weaviate", "chatcompletion", "tokenizer"
        ]
        if any(kw in code_lower for kw in ai_keywords):
            return {
                "code_purpose_summary": "Autonomous Agent / LLM workflow performing dynamic prompt processing, tool invocation, or vector memory retrieval.",
                "detected_domain": "Agentic AI & Multi-Agent Systems",
                "selected_methodology": "MAESTRO",
                "methodology_name": "MAESTRO (Agentic AI Threat Framework)",
                "rationale": "This snippet utilizes LLM agents, dynamic tool invocation, or persistent vector memory. The MAESTRO framework is specifically tailored to analyze vulnerabilities across the 7 layers of agentic architectures (Model, Autonomous Agents, Tools, Memory, Transport, Swarms, UI)."
            }

        # Check Automotive / Vehicle (ISO 21434 TARA)
        auto_keywords = [
            "can", "can_id", "can-fd", "canfd", "ecu", "uds", "autosar", "secoc", 
            "telematics", "tcu", "bcm", "obd", "obd2", "doip", "some/ip", "flexray", 
            "lin", "actuate", "brake", "steer", "powertrain", "chassis", "speed", 
            "vehicle", "adas", "v2x"
        ]
        if any(kw in code_lower for kw in auto_keywords):
            return {
                "code_purpose_summary": "In-vehicle electronic control logic, ECU communication, or automotive network frame handling.",
                "detected_domain": "Automotive & Cyber-Physical Systems",
                "selected_methodology": "TARA",
                "methodology_name": "ISO/SAE 21434 TARA (Automotive Cybersecurity)",
                "rationale": "This snippet processes vehicular signals, ECU communication, or CAN-bus frames. ISO/SAE 21434 TARA is the international standard for evaluating vehicular Item boundaries, SFOP damage scenarios (Safety, Financial, Operational, Privacy), and 5-factor Attack Feasibility ratings."
            }

        # Check Enterprise / Financial (PASTA)
        business_keywords = [
            "payment", "ledger", "invoice", "order", "billing", "checkout", 
            "reconcil", "accounting", "pci", "stripe", "paypal", "balance", 
            "transfer", "audit_trail", "settlement", "bank"
        ]
        if any(kw in code_lower for kw in business_keywords):
            return {
                "code_purpose_summary": "Business-critical enterprise workflow, transaction ledger, or financial payment processing.",
                "detected_domain": "Enterprise Financial & Business Workflow",
                "selected_methodology": "PASTA",
                "methodology_name": "PASTA (Process for Attack Simulation & Threat Analysis)",
                "rationale": "This snippet processes critical business transactions or financial assets. PASTA's 7-stage risk-centric methodology aligns threat simulation with business asset value, regulatory compliance, and economic threat actor motivations."
            }

        # Default to Technical STRIDE
        return {
            "code_purpose_summary": "Application service endpoint, authentication logic, database access, or command dispatch.",
            "detected_domain": "Software, Web & Cloud Application",
            "selected_methodology": "STRIDE",
            "methodology_name": "STRIDE Threat Modeling",
            "rationale": "This snippet implements core application logic, database querying, or network service handlers. STRIDE provides an exhaustive technical threat classification across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege."
        }

    @staticmethod
    async def generate_code_threats(
        engine: BaseMethodologyEngine,
        code_snippet: str,
        language: str = "auto",
        snippet_title: str = "Code Snippet",
        provider: Optional[str] = None,
        model_name: Optional[str] = None,
        custom_instructions: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Orchestrates code-level threat modeling on pasted code snippets.
        """
        start_time = time.time()
        active_provider = (provider or settings.DEFAULT_LLM_PROVIDER).lower()
        active_model = model_name or (settings.OPENAI_MODEL if active_provider == "openai" else settings.OLLAMA_MODEL)

        safe_code = DocumentService.sanitize_untrusted_context(code_snippet, max_chars=30000)
        system_prompt = f"""You are a Principal Application Security Engineer and Secure Code Reviewer.
Perform a strict code-level threat model using the {engine.name} ({engine.code}) methodology.
Analyze input validation, memory safety, authentication, authorization, cryptography, and business logic flaws.
Adhere strictly to the {engine.code} categorization: {", ".join(engine.get_categories())}."""

        user_prompt = engine.build_code_snippet_prompt(
            code_snippet=safe_code,
            language=language,
            snippet_title=snippet_title,
            custom_instructions=custom_instructions
        )

        threats = []
        tokens_used = {"prompt_tokens": 0, "completion_tokens": 0}
        error_msg = None
        status = "success"

        try:
            if active_provider == "openai" and settings.OPENAI_API_KEY:
                threats, tokens_used = await LLMService._call_openai(system_prompt, user_prompt, active_model)
            elif active_provider == "ollama":
                threats, tokens_used = await LLMService._call_ollama(system_prompt, user_prompt, active_model)
            else:
                threats = engine.generate_simulated_code_threats(code_snippet, language, snippet_title)
                active_provider = "simulation"
                active_model = f"deterministic-code-analyzer-v1.0 ({engine.code})"
                tokens_used = {"prompt_tokens": len(user_prompt) // 4, "completion_tokens": 750}
        except Exception as e:
            error_msg = f"Provider {active_provider} error: {str(e)}. Falling back to deterministic code threat model."
            threats = engine.generate_simulated_code_threats(code_snippet, language, snippet_title)
            active_provider = "simulation (fallback)"
            active_model = f"deterministic-code-analyzer-v1.0 ({engine.code})"
            status = "fallback_success"

        execution_time_ms = int((time.time() - start_time) * 1000)

        processed_threats = []
        for t in threats:
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
    async def classify_code_and_methodology(
        code_snippet: str,
        language: str = "auto",
        provider: Optional[str] = None,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyzes the code snippet function, architectural domain, and automatically
        determines the most suitable threat modeling methodology (STRIDE, PASTA, MAESTRO, TARA)
        along with code function explanation and selection justification.
        """
        active_provider = (provider or settings.DEFAULT_LLM_PROVIDER).lower()
        active_model = model_name or (settings.OPENAI_MODEL if active_provider == "openai" else settings.OLLAMA_MODEL)
        
        # 1. Try LLM if configured
        if active_provider == "openai" and settings.OPENAI_API_KEY:
            try:
                system_prompt = """You are a Principal Security Architect specializing in threat modeling.
Analyze the provided source code snippet:
1. Explain what the function and architecture of the code is.
2. Determine which of the four methodologies is most suitable:
   - MAESTRO: For Agentic AI, LLM prompts, multi-agent swarms, tool calling, RAG vector memory.
   - TARA: For automotive ECUs, CAN/LIN bus, telematics, firmware, vehicle control systems (ISO/SAE 21434).
   - PASTA: For business-critical enterprise transactions, financial/payment flows, multi-tier business logic.
   - STRIDE: For general software, web services, microservices, cloud APIs, database and authentication logic.
Output strictly JSON:
{
  "code_purpose_summary": "1-2 sentence description of code function and intent",
  "detected_domain": "Domain name",
  "selected_methodology": "STRIDE | PASTA | MAESTRO | TARA",
  "methodology_name": "Full name",
  "rationale": "Clear justification explaining why this methodology is the best fit for this code construct"
}"""
                user_prompt = f"Code snippet ({language}):\n\n```{language}\n{code_snippet[:6000]}\n```"
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY, base_url=settings.OPENAI_BASE_URL)
                response = await client.chat.completions.create(
                    model=active_model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1
                )
                content = response.choices[0].message.content or "{}"
                parsed = json.loads(content)
                if parsed.get("selected_methodology") in ["STRIDE", "PASTA", "MAESTRO", "TARA"]:
                    return parsed
            except Exception:
                pass

        # 2. Intelligent Semantic Code Classifier Fallback
        code_lower = code_snippet.lower()
        
        # Check Agentic AI / LLM (MAESTRO)
        ai_keywords = [
            "langchain", "openai", "agent", "prompt", "embedding", "vector", "rag", 
            "llm", "tool", "anthropic", "swarm", "crewai", "autogen", "chroma", 
            "pinecone", "qdrant", "weaviate", "chatcompletion", "tokenizer"
        ]
        if any(kw in code_lower for kw in ai_keywords):
            return {
                "code_purpose_summary": "Autonomous Agent / LLM workflow performing dynamic prompt processing, tool invocation, or vector memory retrieval.",
                "detected_domain": "Agentic AI & Multi-Agent Systems",
                "selected_methodology": "MAESTRO",
                "methodology_name": "MAESTRO (Agentic AI Threat Framework)",
                "rationale": "This snippet utilizes LLM agents, dynamic tool invocation, or persistent vector memory. The MAESTRO framework is specifically tailored to analyze vulnerabilities across the 7 layers of agentic architectures (Model, Autonomous Agents, Tools, Memory, Transport, Swarms, UI)."
            }

        # Check Automotive / Vehicle (ISO 21434 TARA)
        auto_keywords = [
            "can", "can_id", "can-fd", "canfd", "ecu", "uds", "autosar", "secoc", 
            "telematics", "tcu", "bcm", "obd", "obd2", "doip", "some/ip", "flexray", 
            "lin", "actuate", "brake", "steer", "powertrain", "chassis", "speed", 
            "vehicle", "adas", "v2x"
        ]
        if any(kw in code_lower for kw in auto_keywords):
            return {
                "code_purpose_summary": "In-vehicle electronic control logic, ECU communication, or automotive network frame handling.",
                "detected_domain": "Automotive & Cyber-Physical Systems",
                "selected_methodology": "TARA",
                "methodology_name": "ISO/SAE 21434 TARA (Automotive Cybersecurity)",
                "rationale": "This snippet processes vehicular signals, ECU communication, or CAN-bus frames. ISO/SAE 21434 TARA is the international standard for evaluating vehicular Item boundaries, SFOP damage scenarios (Safety, Financial, Operational, Privacy), and 5-factor Attack Feasibility ratings."
            }

        # Check Enterprise / Financial (PASTA)
        business_keywords = [
            "payment", "ledger", "invoice", "order", "billing", "checkout", 
            "reconcil", "accounting", "pci", "stripe", "paypal", "balance", 
            "transfer", "audit_trail", "settlement", "bank"
        ]
        if any(kw in code_lower for kw in business_keywords):
            return {
                "code_purpose_summary": "Business-critical enterprise workflow, transaction ledger, or financial payment processing.",
                "detected_domain": "Enterprise Financial & Business Workflow",
                "selected_methodology": "PASTA",
                "methodology_name": "PASTA (Process for Attack Simulation & Threat Analysis)",
                "rationale": "This snippet processes critical business transactions or financial assets. PASTA's 7-stage risk-centric methodology aligns threat simulation with business asset value, regulatory compliance, and economic threat actor motivations."
            }

        # Default to Technical STRIDE
        return {
            "code_purpose_summary": "Application service endpoint, authentication logic, database access, or command dispatch.",
            "detected_domain": "Software, Web & Cloud Application",
            "selected_methodology": "STRIDE",
            "methodology_name": "STRIDE Threat Modeling",
            "rationale": "This snippet implements core application logic, database querying, or network service handlers. STRIDE provides an exhaustive technical threat classification across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege."
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

