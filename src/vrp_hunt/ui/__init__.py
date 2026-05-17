"""Static local dashboard generation."""

from vrp_hunt.ui.dashboard import (
    DashboardApproval,
    DashboardData,
    DashboardEvidence,
    DashboardFinding,
    DashboardSummary,
    DashboardWarning,
    build_dashboard_data,
    render_dashboard_html,
    write_dashboard,
)

__all__ = [
    "DashboardApproval",
    "DashboardData",
    "DashboardEvidence",
    "DashboardFinding",
    "DashboardSummary",
    "DashboardWarning",
    "build_dashboard_data",
    "render_dashboard_html",
    "write_dashboard",
]
