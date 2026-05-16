"""Load and validate the structured VRP ruleset."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from vrp_hunt.guardrails.models import Ruleset

MAX_RULESET_BYTES = 512_000
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_RULES_PATH = REPO_ROOT / "config" / "google_vrp_rules.yaml"
DEFAULT_DIGEST_PATH = REPO_ROOT / "google-alphabet-vrp-rules.md"


class RulesetLoadError(ValueError):
    """Raised when policy data cannot be loaded safely."""


def _read_limited_text(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > MAX_RULESET_BYTES:
        raise RulesetLoadError(f"{path} exceeds size limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RulesetLoadError(f"{path} is not valid UTF-8") from exc


def digest_file_hash(path: Path = DEFAULT_DIGEST_PATH) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_ruleset(
    path: str | Path = DEFAULT_RULES_PATH,
    *,
    digest_path: str | Path = DEFAULT_DIGEST_PATH,
    verify_digest: bool = True,
) -> Ruleset:
    """Load the structured ruleset, rejecting partial or malformed data."""

    rules_path = Path(path)
    digest_file = Path(digest_path)
    try:
        raw = _read_limited_text(rules_path)
        parsed: Any = yaml.safe_load(raw)
    except OSError as exc:
        raise RulesetLoadError(f"failed to read ruleset: {rules_path}") from exc
    except yaml.YAMLError as exc:
        raise RulesetLoadError("ruleset YAML is malformed") from exc

    if not isinstance(parsed, dict):
        raise RulesetLoadError("ruleset root must be a mapping")

    try:
        ruleset = Ruleset.model_validate(parsed)
    except ValidationError as exc:
        raise RulesetLoadError("ruleset validation failed") from exc

    if verify_digest:
        try:
            actual_hash = digest_file_hash(digest_file)
        except OSError as exc:
            raise RulesetLoadError(f"failed to read digest: {digest_file}") from exc
        if actual_hash != ruleset.digest_hash:
            raise RulesetLoadError("ruleset digest hash does not match source digest")

    return ruleset
