"""Model provider clients for agent hypothesis generation."""

from __future__ import annotations

import json
import os
from typing import Any, Literal

import httpx

from vrp_hunt.agent.planner import AgentBrain, HeuristicBrain, ModelBrain
from vrp_hunt.guardrails.audit import SENSITIVE_KEY_PARTS
from vrp_hunt.recon import Asset

REWARD_CATEGORIES = ["S0", "S1", "S2a", "S2b", "S2c", "C0", "C1a", "C1b", "C1c"]
BUG_CLASSES = ["xss", "csrf", "idor", "xsleak", "oauth", "server_side"]
ModelProviderName = Literal["heuristic", "openai"]


class ModelProviderError(RuntimeError):
    """Raised when a model provider call cannot produce valid hypotheses."""


def build_agent_brain(
    *,
    provider: ModelProviderName = "heuristic",
    allow_remote_model: bool = False,
    openai_api_key: str | None = None,
    openai_model: str | None = None,
    openai_base_url: str = "https://api.openai.com/v1",
    timeout_seconds: float = 30.0,
    max_assets: int = 50,
    client: httpx.Client | None = None,
) -> AgentBrain:
    """Build a planner brain, defaulting to local deterministic heuristics."""

    if provider == "heuristic":
        return HeuristicBrain()
    if provider == "openai":
        if not allow_remote_model:
            raise ModelProviderError(
                "remote model provider requires --allow-remote-model acknowledgement"
            )
        if timeout_seconds <= 0:
            raise ModelProviderError("model timeout must be positive")
        if max_assets <= 0:
            raise ModelProviderError("model max assets must be positive")
        return ModelBrain(
            OpenAIResponsesClient(
                api_key=openai_api_key,
                model=openai_model,
                base_url=openai_base_url,
                timeout_seconds=timeout_seconds,
                client=client,
                max_assets=max_assets,
            )
        )
    raise ModelProviderError(f"unsupported model provider: {provider}")


class OpenAIResponsesClient:
    """Structured OpenAI Responses API client for ``ModelBrain``.

    The client sends only recon asset summaries and asks for bounded hypothesis
    labels. It does not request exploit payloads, browser actions, or live target
    interaction.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 30.0,
        client: httpx.Client | None = None,
        max_assets: int = 50,
    ) -> None:
        self._api_key = api_key
        self.model = model or os.getenv("VRP_HUNT_OPENAI_MODEL", "gpt-5.2")
        self.base_url = base_url.rstrip("/")
        self.max_assets = max_assets
        self._client = client or httpx.Client(timeout=timeout_seconds)

    def suggest_hypotheses(self, assets: list[Asset]) -> list[dict[str, Any]]:
        api_key = self._api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ModelProviderError("OPENAI_API_KEY is required for OpenAIResponsesClient")

        response = self._client.post(
            f"{self.base_url}/responses",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=self._payload(assets),
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ModelProviderError(f"OpenAI provider request failed: {exc.response.status_code}") from exc

        return _extract_suggestions(response.json())

    def _payload(self, assets: list[Asset]) -> dict[str, Any]:
        return {
            "model": self.model,
            "instructions": (
                "You generate conservative Google VRP hypothesis labels for an authorized "
                "research assistant. Return only structured JSON. Do not include exploit "
                "payloads, bypass instructions, credential material, or live-test steps. "
                "Prefer low confidence when evidence is weak."
            ),
            "input": json.dumps(
                {
                    "task": "Suggest vulnerability hypotheses from these recon assets.",
                    "assets": [_asset_for_model(asset) for asset in assets[: self.max_assets]],
                    "allowed_bug_classes": BUG_CLASSES,
                    "allowed_reward_categories": REWARD_CATEGORIES,
                },
                sort_keys=True,
            ),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "vrp_hunt_hypotheses",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "suggestions": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "bug_class": {"type": "string", "enum": BUG_CLASSES},
                                        "category": {"type": "string", "enum": REWARD_CATEGORIES},
                                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                                        "reason": {"type": "string", "minLength": 1},
                                    },
                                    "required": [
                                        "bug_class",
                                        "category",
                                        "confidence",
                                        "reason",
                                    ],
                                },
                            }
                        },
                        "required": ["suggestions"],
                    },
                }
            },
        }


def _asset_for_model(asset: Asset) -> dict[str, Any]:
    return {
        "kind": asset.kind,
        "value": _redact_if_sensitive_key(asset.kind, asset.value),
        "source": asset.source,
        "parent": asset.parent,
        "metadata": {
            key: _redact_if_sensitive_key(key, value)
            for key, value in sorted(asset.metadata.items())
        },
    }


def _redact_if_sensitive_key(key: str, value: str) -> str:
    lowered = key.lower()
    if any(part in lowered for part in SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    return value


def _extract_suggestions(data: dict[str, Any]) -> list[dict[str, Any]]:
    output_text = _extract_output_text(data)
    try:
        parsed = json.loads(output_text)
    except json.JSONDecodeError as exc:
        raise ModelProviderError("OpenAI provider did not return JSON output") from exc

    suggestions = parsed.get("suggestions")
    if not isinstance(suggestions, list):
        raise ModelProviderError("OpenAI provider output missing suggestions list")
    if not all(isinstance(item, dict) for item in suggestions):
        raise ModelProviderError("OpenAI provider suggestions must be objects")
    return suggestions


def _extract_output_text(data: dict[str, Any]) -> str:
    direct = data.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct

    texts: list[str] = []
    output = data.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for content_item in content:
                if not isinstance(content_item, dict):
                    continue
                text = content_item.get("text")
                if isinstance(text, str):
                    texts.append(text)
    combined = "".join(texts).strip()
    if not combined:
        raise ModelProviderError("OpenAI provider response had no text output")
    return combined
