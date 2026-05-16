import asyncio
from datetime import date

import pytest

from vrp_hunt.guardrails import GuardrailGate, RateLimitPolicy
from vrp_hunt.recon import AsyncPoliteScheduler, GateDeniedError, HttpRequest, HttpResponse


def run(coro):
    return asyncio.run(coro)


class FakeTransport:
    def __init__(self, responses: list[HttpResponse] | None = None) -> None:
        self.calls: list[HttpRequest] = []
        self.responses = responses or [HttpResponse(status_code=200, text="ok")]

    async def __call__(self, request: HttpRequest) -> HttpResponse:
        self.calls.append(request)
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


class SleepRecorder:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def scheduler(transport: FakeTransport, sleep: SleepRecorder | None = None) -> AsyncPoliteScheduler:
    return AsyncPoliteScheduler(
        gate=GuardrailGate(as_of_date=date(2026, 5, 16)),
        rate_policy=RateLimitPolicy(global_max_rps=1000, per_host_max_rps=1000, retry_budget=1),
        transport=transport,
        sleep=sleep or SleepRecorder(),
        jitter=lambda _cap: 0.25,
    )


def test_gate_deny_prevents_transport_call() -> None:
    transport = FakeTransport()
    polite = scheduler(transport)

    with pytest.raises(GateDeniedError):
        run(polite.request(HttpRequest(url="https://example.com/")))

    assert transport.calls == []


def test_allowed_request_calls_transport_once() -> None:
    transport = FakeTransport()
    polite = scheduler(transport)

    response = run(polite.request(HttpRequest(url="https://www.google.com/")))

    assert response.status_code == 200
    assert len(transport.calls) == 1


def test_identical_concurrent_requests_single_flight() -> None:
    transport = FakeTransport()
    polite = scheduler(transport)

    async def scenario() -> list[HttpResponse]:
        request = HttpRequest(url="https://www.google.com/")
        return await asyncio.gather(polite.request(request), polite.request(request))

    responses = run(scenario())

    assert [response.status_code for response in responses] == [200, 200]
    assert len(transport.calls) == 1


def test_retry_after_controls_sleep_delay() -> None:
    sleep = SleepRecorder()
    transport = FakeTransport(
        [
            HttpResponse(status_code=429, headers={"Retry-After": "2"}),
            HttpResponse(status_code=200, text="ok"),
        ]
    )
    polite = scheduler(transport, sleep)

    response = run(polite.request(HttpRequest(url="https://www.google.com/")))

    assert response.status_code == 200
    assert 2.0 in sleep.delays
    assert len(transport.calls) == 2
