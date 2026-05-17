import pytest
from pydantic import ValidationError

from vrp_hunt.recon import HttpRequest, HttpResponse, HttpxTransport, NucleiCommandBuilder
from vrp_hunt.recon.wrappers import NucleiTemplatePolicy


class FakeHttpxResponse:
    status_code = 204
    headers = {"content-type": "text/plain"}
    text = ""
    url = "https://www.google.com/"


class FakeHttpxClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def request(self, method: str, url: str, **_kwargs: object) -> FakeHttpxResponse:
        self.calls.append((method, url))
        return FakeHttpxResponse()


def test_httpx_transport_normalizes_response() -> None:
    import asyncio

    client = FakeHttpxClient()
    transport = HttpxTransport(client)
    response = asyncio.run(transport(HttpRequest(method="GET", url="https://www.google.com/")))

    assert isinstance(response, HttpResponse)
    assert response.status_code == 204
    assert client.calls == [("GET", "https://www.google.com/")]


def test_nuclei_policy_requires_explicit_templates() -> None:
    with pytest.raises(ValidationError):
        NucleiTemplatePolicy(templates=[])
    with pytest.raises(ValidationError):
        NucleiTemplatePolicy(templates=["../unsafe.yaml"])


def test_nuclei_policy_blocks_aggressive_tags() -> None:
    with pytest.raises(ValidationError):
        NucleiTemplatePolicy(templates=["safe/http/title.yaml"], tags=["dos"])
    with pytest.raises(ValidationError):
        NucleiTemplatePolicy(templates=["safe/http/title.yaml"], tags=["dast"])


def test_nuclei_policy_blocks_non_http_protocols() -> None:
    with pytest.raises(ValidationError):
        NucleiTemplatePolicy(templates=["safe/http/title.yaml"], protocol_types=["tcp"])


def test_nuclei_command_builder_outputs_args_without_running() -> None:
    policy = NucleiTemplatePolicy(templates=["safe/http/title.yaml"], tags=["exposure"])
    command = NucleiCommandBuilder(policy=policy).build("targets.txt", rate_limit=0.2)

    assert command[:2] == ["nuclei", "-list"]
    assert "targets.txt" in command
    assert "safe/http/title.yaml" in command
    assert "-rl" in command
    assert "-j" in command
    assert "-silent" in command
    assert "-ni" in command
    assert command[-2:] == ["-pt", "http"]
