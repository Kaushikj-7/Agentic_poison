"""Gemini API Runner for opt-in evaluation tier.

Provides an interface to test AgentPOI's defenses against Gemini.
Enforces Rule 5 by requiring explicit opt-in, as it relies on external network access.
Detects API key expiration and securely raises a clear alert without hardcoding secrets.
"""

import os
from typing import Optional

try:
    from google import genai
    from google.genai import errors
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False


class GeminiRunner:
    """Opt-in Gemini API wrapper for architecture testing."""

    def __init__(self, model_name: str = "gemini-3.6-flash"):
        if not HAS_GENAI:
            raise ImportError(
                "google-genai is not installed. "
                "Run `pip install google-genai` to use GeminiRunner."
            )
        
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "[CRITICAL] GEMINI_API_KEY not found in environment. "
                "Please add it to the local .env file. (Do not hardcode it in Python!)"
            )
        
        self.client = genai.Client(api_key=api_key)
        self.model_name = model_name

    def generate(self, prompt: str, system_instruction: Optional[str] = None) -> str:
        """Generate content from the Gemini model.
        
        Args:
            prompt: The user input or prompt injection payload.
            system_instruction: Optional system prompt to guide the model.
            
        Returns:
            The raw text string from the model.
        """
        try:
            full_prompt = prompt
            if system_instruction:
                full_prompt = f"{system_instruction}\n\n{prompt}"
                
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=full_prompt
            )
            return response.text
        except errors.ClientError as e:
            # Workspace constraint: Alert the user cleanly when the key expires or is unauthorized.
            error_msg = (
                "\n[CRITICAL] Gemini API Key has EXPIRED, is INVALID, or lacks permissions.\n"
                "Please generate a new key and update the local .env file.\n"
                f"Underlying error: {str(e)}\n"
            )
            print(error_msg)
            raise RuntimeError(error_msg) from e
