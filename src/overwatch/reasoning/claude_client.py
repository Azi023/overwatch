"""
Claude API client for Overwatch V2.

Provides tiered model selection (Haiku/Sonnet/Opus), structured responses,
JSON extraction, and retry logic with exponential backoff.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import anthropic

logger = logging.getLogger(__name__)

# ──────────────────────────── Model constants ────────────────────────────

HAIKU_MODEL = "claude-haiku-4-5-20251001"
SONNET_MODEL = "claude-sonnet-4-6"
OPUS_MODEL = "claude-opus-4-6"

# Pricing per million tokens (input / output)
_PRICING: Dict[str, Dict[str, float]] = {
    HAIKU_MODEL:  {"input": 0.80,  "output": 4.00},
    SONNET_MODEL: {"input": 3.00,  "output": 15.00},
    OPUS_MODEL:   {"input": 15.00, "output": 75.00},
}

# Task types → model tier
_HAIKU_TASKS = frozenset({
    "log_parsing",
    "classification",
    "simple_extraction",
    "port_classification",
    "severity_label",
    "tech_detection",
    "header_analysis",
})

_OPUS_TASKS = frozenset({
    "complex_chain",
    "attack_chain_analysis",
    "multi_step_exploitation",
    "strategic_planning",
    "full_engagement_plan",
})

MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 2.0


# ──────────────────────────── Response dataclass ────────────────────────────

@dataclass(frozen=True)
class ClaudeResponse:
    """Immutable response from the Claude API."""

    content: str
    model_used: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    stop_reason: str = "end_turn"
    raw_json: Optional[Dict[str, Any]] = field(default=None, compare=False)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


# ──────────────────────────── Helpers ────────────────────────────

def _select_model(task_type: str) -> str:
    """Return the appropriate model name for the given task type."""
    if task_type in _HAIKU_TASKS:
        return HAIKU_MODEL
    if task_type in _OPUS_TASKS:
        return OPUS_MODEL
    return SONNET_MODEL


def _calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate API cost in USD."""
    pricing = _PRICING.get(model, _PRICING[SONNET_MODEL])
    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]
    return round(input_cost + output_cost, 8)


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract a JSON object from text that may contain markdown code fences.

    Strips ```json ... ``` and ``` ... ``` blocks before parsing.
    Falls back to attempting to parse the raw text.
    Returns None if no valid JSON can be extracted.
    """
    # Strip markdown code fences
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        candidate = fenced.group(1)
    else:
        # Try to find the first {...} block in the text
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        candidate = brace_match.group(0) if brace_match else text

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        logger.debug("JSON extraction failed for text snippet: %s…", text[:120])
        return None


def extract_json_list(text: str) -> Optional[List[Any]]:
    """Extract a JSON array from text that may contain markdown code fences."""
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
    if fenced:
        candidate = fenced.group(1)
    else:
        bracket_match = re.search(r"\[.*\]", text, re.DOTALL)
        candidate = bracket_match.group(0) if bracket_match else text

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        logger.debug("JSON list extraction failed for text snippet: %s…", text[:120])
        return None


# ──────────────────────────── Client ────────────────────────────

class ClaudeClient:
    """
    Async Claude API client with tiered model selection and retry logic.

    Usage::

        client = ClaudeClient()
        response = await client.complete(
            task_type="analysis",
            messages=[{"role": "user", "content": "Analyze this scan output..."}],
            system_prompt="You are a security analyst.",
        )
        print(response.content)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        max_retries: int = MAX_RETRIES,
        base_backoff: float = BASE_BACKOFF_SECONDS,
        default_max_tokens: int = 4096,
    ) -> None:
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise ValueError(
                "ANTHROPIC_API_KEY must be set in the environment or passed explicitly."
            )

        self._client = anthropic.AsyncAnthropic(api_key=resolved_key)
        self._max_retries = max_retries
        self._base_backoff = base_backoff
        self._default_max_tokens = default_max_tokens

    async def complete(
        self,
        task_type: str,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        model_override: Optional[str] = None,
        temperature: float = 0.2,
    ) -> ClaudeResponse:
        """
        Send a completion request to the Claude API.

        Args:
            task_type:      Logical task category (drives model selection).
            messages:       List of {"role": "user"|"assistant", "content": "..."} dicts.
            system_prompt:  Optional system-level instructions.
            max_tokens:     Override the default max output tokens.
            model_override: Force a specific model, bypassing auto-selection.
            temperature:    Sampling temperature (lower = more deterministic).

        Returns:
            ClaudeResponse with content, token counts, and cost.

        Raises:
            anthropic.APIError: After all retries are exhausted.
        """
        model = model_override or _select_model(task_type)
        tokens = max_tokens or self._default_max_tokens

        kwargs: Dict[str, Any] = {
            "model": model,
            "max_tokens": tokens,
            "messages": messages,
            "temperature": temperature,
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        last_exc: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                api_response = await self._client.messages.create(**kwargs)

                content_text = ""
                if api_response.content:
                    content_text = api_response.content[0].text

                input_tokens = api_response.usage.input_tokens
                output_tokens = api_response.usage.output_tokens
                cost = _calculate_cost(model, input_tokens, output_tokens)

                logger.debug(
                    "Claude %s response: %d in / %d out tokens, $%.6f",
                    model,
                    input_tokens,
                    output_tokens,
                    cost,
                )

                return ClaudeResponse(
                    content=content_text,
                    model_used=model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cost_usd=cost,
                    stop_reason=api_response.stop_reason or "end_turn",
                )

            except anthropic.RateLimitError as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    backoff = self._base_backoff * (2 ** attempt)
                    logger.warning(
                        "Rate limit hit (attempt %d/%d). Backing off %.1fs.",
                        attempt + 1,
                        self._max_retries + 1,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    logger.error("Rate limit persists after %d retries.", self._max_retries)
                    raise

            except anthropic.APIStatusError as exc:
                # Retry on 5xx server errors; raise immediately on 4xx
                if exc.status_code >= 500 and attempt < self._max_retries:
                    last_exc = exc
                    backoff = self._base_backoff * (2 ** attempt)
                    logger.warning(
                        "Server error %d (attempt %d/%d). Backing off %.1fs.",
                        exc.status_code,
                        attempt + 1,
                        self._max_retries + 1,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    raise

        # Should not be reached, but satisfy the type checker
        raise last_exc  # type: ignore[misc]

    async def complete_with_json(
        self,
        task_type: str,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        model_override: Optional[str] = None,
    ) -> tuple[ClaudeResponse, Optional[Dict[str, Any]]]:
        """
        Convenience wrapper that calls complete() and also attempts JSON extraction.

        Returns:
            (ClaudeResponse, parsed_dict_or_None)
        """
        response = await self.complete(
            task_type=task_type,
            messages=messages,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            model_override=model_override,
        )
        parsed = extract_json(response.content)
        return response, parsed

    def get_pricing(self, model: Optional[str] = None) -> Dict[str, float]:
        """Return pricing info for the given model (defaults to Sonnet)."""
        return _PRICING.get(model or SONNET_MODEL, _PRICING[SONNET_MODEL])
