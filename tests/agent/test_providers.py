import json
from decimal import Decimal

import httpx
import pytest

from vrp_hunt.agent import (
    HeuristicBrain,
    ModelBrain,
    ModelProviderError,
    OpenAIResponsesClient,
    build_agent_brain,
)
from vrp_hunt.recon import Asset


def test_openai_responses_client_posts_structured_request_and_parses_output() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers["authorization"]
        payload = json.loads(request.content)
        captured["payload"] = payload
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {
                                "type": "output_text",
                                "text": json.dumps(
                                    {
                                        "suggestions": [
                                            {
                                                "bug_class": "oauth",
                                                "category": "C1b",
                                                "confidence": 0.61,
                                                "reason": "OAuth path indicators are present.",
                                            }
                                        ]
                                    }
                                ),
                            }
                        ],
                    }
                ]
            },
        )

    provider = OpenAIResponsesClient(
        api_key="test-key",
        model="gpt-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    suggestions = ModelBrain(provider).suggest(
        [
            Asset(
                kind="url",
                value="https://accounts.google.com/o/oauth2/v2/auth",
                source="test",
                metadata={"cookie": "SID=secret"},
            )
        ]
    )

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert captured["authorization"] == "Bearer test-key"
    assert payload["model"] == "gpt-test"
    assert payload["text"]["format"]["type"] == "json_schema"
    assert "[REDACTED]" in payload["input"]
    assert suggestions[0].bug_class == "oauth"
    assert suggestions[0].confidence == Decimal("0.61")


def test_openai_responses_client_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIResponsesClient(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200))))

    with pytest.raises(ModelProviderError, match="OPENAI_API_KEY"):
        provider.suggest_hypotheses([])


def test_build_agent_brain_defaults_to_local_heuristics() -> None:
    brain = build_agent_brain(provider="heuristic")

    assert isinstance(brain, HeuristicBrain)


def test_build_agent_brain_requires_remote_model_acknowledgement() -> None:
    with pytest.raises(ModelProviderError, match="allow-remote-model"):
        build_agent_brain(provider="openai", openai_api_key="test-key")


def test_build_agent_brain_wires_openai_provider() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        payload = json.loads(request.content)
        captured["model"] = payload["model"]
        return httpx.Response(
            200,
            json={
                "output_text": json.dumps(
                    {
                        "suggestions": [
                            {
                                "bug_class": "idor",
                                "category": "S2b",
                                "confidence": 0.7,
                                "reason": "Account object indicators are present.",
                            }
                        ]
                    }
                )
            },
        )

    brain = build_agent_brain(
        provider="openai",
        allow_remote_model=True,
        openai_api_key="test-key",
        openai_model="gpt-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    suggestions = brain.suggest(
        [Asset(kind="url", value="https://accounts.google.com/profile", source="test")]
    )

    assert captured["url"] == "https://api.openai.com/v1/responses"
    assert captured["model"] == "gpt-test"
    assert suggestions[0].bug_class == "idor"
