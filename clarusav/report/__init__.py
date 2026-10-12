"""Reporting, visualization, and alerting package for ClarusAV."""

from clarusav.report.renderer import (
    DriftMonitor,
    EntropyHeatmap,
    HTMLReportGenerator,
    SectionEntropyInfo,
)
from clarusav.report.sarif import generate_sarif_report

# Aliases for backward compatibility
EntropyHeatmapRenderer = EntropyHeatmap
ScanHTMLReport = HTMLReportGenerator

__all__ = [
    "DriftMonitor",
    "EntropyHeatmap",
    "EntropyHeatmapRenderer",
    "HTMLReportGenerator",
    "ScanHTMLReport",
    "SectionEntropyInfo",
    "generate_sarif_report",
]
