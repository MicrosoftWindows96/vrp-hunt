"""Web recon adapter for the shared recon framework."""

from vrp_hunt.web_recon.adapter import WebReconAdapter
from vrp_hunt.web_recon.extractors import (
    extract_endpoint_paths,
    extract_javascript_urls,
    extract_parameter_names,
    extract_secret_notes,
)
from vrp_hunt.web_recon.models import CommandResult, WebReconConfig
from vrp_hunt.web_recon.parsers import parse_amass_text, parse_httpx_jsonl, parse_subfinder_jsonl
from vrp_hunt.web_recon.tools import (
    SubprocessCommandRunner,
    build_amass_command,
    build_httpx_command,
    build_subfinder_command,
)

__all__ = [
    "CommandResult",
    "SubprocessCommandRunner",
    "WebReconAdapter",
    "WebReconConfig",
    "build_amass_command",
    "build_httpx_command",
    "build_subfinder_command",
    "extract_endpoint_paths",
    "extract_javascript_urls",
    "extract_parameter_names",
    "extract_secret_notes",
    "parse_amass_text",
    "parse_httpx_jsonl",
    "parse_subfinder_jsonl",
]
