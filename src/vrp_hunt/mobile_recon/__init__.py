"""Mobile recon adapter for the shared recon framework."""

from vrp_hunt.mobile_recon.adapter import MobileReconAdapter
from vrp_hunt.mobile_recon.extractors import (
    AndroidManifestPermissionRiskSummary,
    AndroidPermissionRisk,
    classify_android_permission_risk,
    extract_certificate_pinning_indicators,
    extract_mobile_endpoints,
    extract_mobile_risk_notes,
    extract_mobile_secret_notes,
    parse_android_manifest,
    parse_dynamic_messages,
    summarize_android_manifest_permissions,
)
from vrp_hunt.mobile_recon.hypotheses import (
    MobileStaticHypothesis,
    MobileStaticReport,
    build_mobile_static_hypotheses,
    build_mobile_static_report,
)
from vrp_hunt.mobile_recon.importer import (
    MobileArtifactImportError,
    MobileArtifactImportReport,
    MobileImportRecord,
    import_apk_artifact,
    import_jadx_output,
    import_mobile_artifacts,
    import_mobsf_static_report,
)
from vrp_hunt.mobile_recon.models import MobileAppTarget, MobileReconConfig
from vrp_hunt.mobile_recon.tools import (
    build_emulator_list_command,
    build_emulator_start_command,
    build_frida_ps_command,
    build_frida_script_command,
    build_jadx_command,
    build_objection_explore_command,
)

__all__ = [
    "MobileAppTarget",
    "MobileArtifactImportError",
    "MobileArtifactImportReport",
    "MobileImportRecord",
    "AndroidManifestPermissionRiskSummary",
    "AndroidPermissionRisk",
    "MobileReconAdapter",
    "MobileReconConfig",
    "MobileStaticHypothesis",
    "MobileStaticReport",
    "build_emulator_list_command",
    "build_emulator_start_command",
    "build_frida_ps_command",
    "build_frida_script_command",
    "build_jadx_command",
    "build_mobile_static_hypotheses",
    "build_mobile_static_report",
    "build_objection_explore_command",
    "classify_android_permission_risk",
    "extract_certificate_pinning_indicators",
    "extract_mobile_endpoints",
    "extract_mobile_risk_notes",
    "extract_mobile_secret_notes",
    "import_apk_artifact",
    "import_jadx_output",
    "import_mobile_artifacts",
    "import_mobsf_static_report",
    "parse_android_manifest",
    "parse_dynamic_messages",
    "summarize_android_manifest_permissions",
]
