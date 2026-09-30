"""
Ollama HTTP client for LLM interactions.

Communicates with a locally running Ollama instance to generate
plain-language vulnerability explanations and fix suggestions.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from src.models.schemas import LLMConfig

logger = logging.getLogger(__name__)


class OllamaClient:
    """
    HTTP client for the Ollama local LLM runtime.
    
    Provides health checking and text generation capabilities.
    """

    def __init__(self, config: LLMConfig | None = None):
        self.config = config or LLMConfig()
        self._base_url = self.config.base_url.rstrip("/")

    def is_available(self) -> bool:
        """
        Check if Ollama is running and the configured model is available.
        
        Returns:
            True if Ollama is reachable and the model is loaded.
        """
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{self._base_url}/api/tags")
                if resp.status_code != 200:
                    return False
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                # Check if the configured model (or a variant) is available
                model_base = self.config.model.split(":")[0]
                available = any(model_base in m for m in models)
                if not available:
                    logger.warning(
                        "Ollama is running but model '%s' not found. Available: %s",
                        self.config.model,
                        models,
                    )
                return available
        except Exception as e:
            logger.debug("Ollama not available: %s", e)
            return False

    def generate(self, prompt: str) -> str | None:
        """
        Send a prompt to Ollama and return the generated text.
        
        Args:
            prompt: The prompt to send to the LLM.
            
        Returns:
            Generated text, or None if generation fails.
        """
        try:
            payload = {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                },
            }

            headers = dict(self.config.extra_headers)
            if self.config.api_key:
                headers.setdefault("Authorization", f"Bearer {self.config.api_key}")
            with httpx.Client(timeout=self.config.timeout, headers=headers) as client:
                resp = client.post(
                    f"{self._base_url}/api/generate",
                    json=payload,
                )

            if resp.status_code != 200:
                logger.error("Ollama returned status %d: %s", resp.status_code, resp.text[:200])
                return None

            data = resp.json()
            return data.get("response", "")

        except httpx.TimeoutException:
            logger.warning("Ollama request timed out after %ds", self.config.timeout)
            return None
        except Exception as e:
            logger.error("Ollama generation failed: %s", e)
            return None

    def generate_json(self, prompt: str) -> dict[str, Any] | None:
        """
        Send a prompt to Ollama expecting a JSON response.
        
        Parses the response as JSON. Returns None if parsing fails.
        """
        raw = self.generate(prompt)
        if raw is None:
            return None

        # Try to extract JSON from the response (LLM may include markdown fences)
        text = raw.strip()
        if text.startswith("```"):
            # Remove markdown code fences
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object within the text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass

            logger.warning("Failed to parse LLM output as JSON: %s", text[:200])
            return None
