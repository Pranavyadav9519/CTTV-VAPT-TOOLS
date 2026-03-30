"""
Reporting Package
Bug-bounty-style penetration report generation for CCTV VAPT assessments.
Includes attack narrative engine and multi-format report builder.
"""

from .narrative_engine import NarrativeEngine
from .report_builder import ReportBuilder

__all__ = ["NarrativeEngine", "ReportBuilder"]
