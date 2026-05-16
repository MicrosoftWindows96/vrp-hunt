"""Gate-checked polite async scheduler."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from time import monotonic
from urllib.parse import urlsplit

from vrp_hunt.guardrails import GuardrailGate, RateLimitPolicy, TargetCandidate
from vrp_hunt.recon.models import HttpRequest, HttpResponse

Transport = Callable[[HttpRequest], Awaitable[HttpResponse]]
SleepFunc = Callable[[float], Awaitable[None]]
ClockFunc = Callable[[], float]
JitterFunc = Callable[[float], float]


class GateDeniedError(RuntimeError):
    """Raised when the guardrail gate denies a request."""


class AsyncPoliteScheduler:
    def __init__(
        self,
        *,
        gate: GuardrailGate,
        rate_policy: RateLimitPolicy,
        transport: Transport,
        sleep: SleepFunc = asyncio.sleep,
        clock: ClockFunc = monotonic,
        jitter: JitterFunc | None = None,
    ) -> None:
        self.gate = gate
        self.rate_policy = rate_policy
        self.transport = transport
        self.sleep = sleep
        self.clock = clock
        self.jitter = jitter or (lambda cap: random.uniform(0, cap))
        self._lock = asyncio.Lock()
        self._global_next_at = 0.0
        self._host_next_at: dict[str, float] = {}
        self._in_flight: dict[str, asyncio.Task[HttpResponse]] = {}

    async def request(self, request: HttpRequest, *, scope: TargetCandidate | None = None) -> HttpResponse:
        candidate = scope or self._candidate_from_request(request)
        decision = self.gate.decide(candidate)
        if not decision.allowed:
            raise GateDeniedError(f"{decision.rule_id}: {decision.reason}")

        key = f"{request.method} {request.url}"
        if self.rate_policy.require_single_flight:
            existing = self._in_flight.get(key)
            if existing is not None:
                return await existing
            task = asyncio.create_task(self._request_with_retries(request))
            self._in_flight[key] = task
            try:
                return await task
            finally:
                self._in_flight.pop(key, None)

        return await self._request_with_retries(request)

    async def _request_with_retries(self, request: HttpRequest) -> HttpResponse:
        attempts = self.rate_policy.retry_budget + 1
        last_response: HttpResponse | None = None
        for attempt in range(attempts):
            await self._wait_for_turn(request.url)
            try:
                response = await self.transport(request)
            except Exception:
                if attempt >= attempts - 1:
                    raise
                await self.sleep(self._backoff_delay(attempt))
                continue

            last_response = response
            if response.status_code not in {429, 503} or attempt >= attempts - 1:
                return response
            retry_after = response.retry_after_seconds()
            await self.sleep(retry_after if retry_after is not None else self._backoff_delay(attempt))

        assert last_response is not None
        return last_response

    async def _wait_for_turn(self, url: str) -> None:
        host = urlsplit(url).hostname or url
        async with self._lock:
            now = self.clock()
            wait_until = max(self._global_next_at, self._host_next_at.get(host, 0.0))
            delay = max(0.0, wait_until - now)
            scheduled_at = now + delay
            self._global_next_at = scheduled_at + (1.0 / self.rate_policy.global_max_rps)
            self._host_next_at[host] = scheduled_at + (1.0 / self.rate_policy.per_host_max_rps)
        if delay > 0:
            await self.sleep(delay)

    def _backoff_delay(self, attempt: int) -> float:
        cap = min(
            self.rate_policy.backoff_cap_seconds,
            self.rate_policy.backoff_base_seconds * (2 ** attempt),
        )
        return self.jitter(cap)

    @staticmethod
    def _candidate_from_request(request: HttpRequest) -> TargetCandidate:
        return TargetCandidate(
            kind="url",
            raw_target=request.url,
            intended_action="recon",
            researcher_owned_account=True,
            will_access_third_party_data=False,
            legal_acknowledged=True,
        )
