"""Browser workflow plans for owned-account validation."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from vrp_hunt.guardrails.models import StrictModel

BrowserStepKind = Literal[
    "login",
    "session_capture",
    "ui_drive",
    "screenshot",
    "video",
    "burp_proxy",
    "burp_replay",
]


class BrowserWorkflowStep(StrictModel):
    kind: BrowserStepKind
    title: str = Field(min_length=1)
    instruction: str = Field(min_length=1)
    requires_human_approval: bool = False
    evidence_refs: list[str] = Field(default_factory=list)


class BrowserWorkflow(StrictModel):
    target: str = Field(min_length=1)
    account_id: str = Field(min_length=1)
    steps: list[BrowserWorkflowStep] = Field(min_length=1)
    owned_account_only: bool = True
    allows_account_creation: bool = False
    burp_proxy: str | None = None

    @model_validator(mode="after")
    def enforce_owned_browser_boundary(self) -> "BrowserWorkflow":
        if not self.owned_account_only:
            raise ValueError("browser workflows must be limited to owned accounts")
        if self.allows_account_creation:
            raise ValueError("browser workflows must not automate account creation")
        return self


def build_owned_account_browser_workflow(
    *,
    target: str,
    account_id: str,
    burp_proxy: str | None = "http://127.0.0.1:8080",
    include_video: bool = True,
) -> BrowserWorkflow:
    steps = [
        BrowserWorkflowStep(
            kind="burp_proxy",
            title="Configure Burp proxy",
            instruction="Use the approved local Burp proxy with passive logging only.",
            evidence_refs=["burp-project-note"],
        ),
        BrowserWorkflowStep(
            kind="login",
            title="Load owned-account session",
            instruction="Authenticate using an existing owned test account secret reference.",
            requires_human_approval=True,
            evidence_refs=["owned-account-note"],
        ),
        BrowserWorkflowStep(
            kind="session_capture",
            title="Record session boundary",
            instruction="Record cookie names and roles without storing cookie values in artifacts.",
            evidence_refs=["redacted-session-summary"],
        ),
        BrowserWorkflowStep(
            kind="ui_drive",
            title="Drive target UI",
            instruction="Perform the minimal owned-account UI path needed for validation.",
            requires_human_approval=True,
            evidence_refs=["http-log", "ui-notes"],
        ),
        BrowserWorkflowStep(
            kind="screenshot",
            title="Capture screenshot",
            instruction="Capture a redacted screenshot of the owned-account result state.",
            evidence_refs=["screenshot"],
        ),
    ]
    if include_video:
        steps.append(
            BrowserWorkflowStep(
                kind="video",
                title="Capture video",
                instruction="Capture a short redacted reproduction video when needed for clarity.",
                evidence_refs=["video"],
            )
        )
    steps.append(
        BrowserWorkflowStep(
            kind="burp_replay",
            title="Prepare Burp replay",
            instruction="Keep replay manual, low-volume, and limited to owned test objects.",
            requires_human_approval=True,
            evidence_refs=["burp-repeater-export"],
        )
    )
    return BrowserWorkflow(
        target=target,
        account_id=account_id,
        steps=steps,
        burp_proxy=burp_proxy,
    )
