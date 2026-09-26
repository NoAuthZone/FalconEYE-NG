"""JSON formatter for machine-readable output."""

import json
from typing import Dict, Any
from ...domain.models.security import SecurityReview, SecurityFinding
from .base_formatter import OutputFormatter
from ... import __version__


class JSONFormatter(OutputFormatter):
    """
    Format security review results as JSON.

    Provides machine-readable output for programmatic consumption,
    CI/CD integration, and further processing.
    """

    def __init__(self, pretty: bool = True):
        """
        Initialize JSON formatter.

        Args:
            pretty: Enable pretty-printing with indentation
        """
        self.pretty = pretty

    def format_review(self, review: SecurityReview) -> str:
        """
        Format complete security review as JSON.

        Args:
            review: SecurityReview to format

        Returns:
            JSON string
        """
        data = self._review_to_dict(review)

        if self.pretty:
            return json.dumps(data, indent=2, default=str)
        else:
            return json.dumps(data, default=str)

    def format_finding(self, finding: SecurityFinding) -> str:
        """
        Format single security finding as JSON.

        Args:
            finding: SecurityFinding to format

        Returns:
            JSON string
        """
        data = self._finding_to_dict(finding)

        if self.pretty:
            return json.dumps(data, indent=2, default=str)
        else:
            return json.dumps(data, default=str)

    def get_file_extension(self) -> str:
        """Get file extension."""
        return ".json"

    def _review_to_dict(self, review: SecurityReview) -> Dict[str, Any]:
        """
        Convert SecurityReview to dictionary.

        Args:
            review: SecurityReview to convert

        Returns:
            Dictionary representation
        """
        return {
            "tool": {
                "name": "FalconEYE",
                "version": __version__,
                "analysis_type": "AI-powered security analysis (NO pattern matching)",
            },
            "review": {
                "id": str(review.id),
                "codebase_path": review.codebase_path,
                "language": review.language,
                "languages": review.get_all_languages(),
                "started_at": review.started_at.isoformat() if review.started_at else None,
                "completed_at": review.completed_at.isoformat() if review.completed_at else None,
                "files_analyzed": review.files_analyzed,
            },
            "summary": {
                "total_findings": len(review.findings),
                "critical": review.get_critical_count(),
                "high": review.get_high_count(),
                "medium": review.get_medium_count(),
                "low": review.get_low_count(),
            },
            "findings": [self._finding_to_dict(f) for f in review.findings],
        }

    def _finding_to_dict(self, finding: SecurityFinding) -> Dict[str, Any]:
        """
        Convert SecurityFinding to dictionary.

        Args:
            finding: SecurityFinding to convert

        Returns:
            Dictionary representation
        """
        return {
            "id": str(finding.id),
            "issue": finding.issue,
            "severity": finding.severity.value,
            "confidence": {
                "value": finding.confidence.value,
                "level": finding.confidence.name.lower(),
            },
            "reasoning": finding.reasoning,
            "mitigation": finding.mitigation,
            "location": {
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
            },
            "code_snippet": finding.code_snippet,
        }