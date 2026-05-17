"""Static local dashboard generation."""

from vrp_hunt.ui.dashboard import (
    DashboardApproval,
    DashboardArtifactPreview,
    DashboardData,
    DashboardEvidence,
    DashboardFinding,
    DashboardProgramOverview,
    DashboardSummary,
    DashboardTimelineEntry,
    DashboardWarning,
    build_dashboard_data,
    render_dashboard_html,
    write_dashboard,
)

__all__ = [
    "DashboardApproval",
    "DashboardArtifactPreview",
    "DashboardData",
    "DashboardEvidence",
    "DashboardFinding",
    "DashboardProgramOverview",
    "DashboardSummary",
    "DashboardTimelineEntry",
    "DashboardWarning",
    "build_dashboard_data",
    "render_dashboard_html",
    "write_dashboard",
]
