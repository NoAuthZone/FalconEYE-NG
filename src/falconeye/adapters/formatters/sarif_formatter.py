"""SARIF formatter for tool integration."""

import json
from typing import Dict, Any, List
from ...domain.models.security import SecurityReview, SecurityFinding, Severity
from .base_formatter import OutputFormatter
from ... import __version__


class SARIFFormatter(OutputFormatter):
    """
    Format security review results as SARIF 2.1.0.

    SARIF (Static Analysis Results Interchange Format) is the industry
    standard for security tool output. Supported by GitHub Security,
    GitLab, Azure DevOps, and other platforms.

    Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

    def __init__(self):
        """Initialize SARIF formatter."""
        pass

    def format_review(self, review: SecurityReview) -> str:
        """
        Format complete security review as SARIF.

        Args:
            review: SecurityReview to format

        Returns:
            SARIF JSON string
        """
        sarif = self._create_sarif_document(review)
        return json.dumps(sarif, indent=2, default=str)

    def format_finding(self, finding: SecurityFinding) -> str:
        """
        Format single security finding as SARIF result.

        Args:
            finding: SecurityFinding to format

        Returns:
            SARIF result JSON string
        """
        result = self._finding_to_sarif_result(finding)
        return json.dumps(result, indent=2, default=str)

    def get_file_extension(self) -> str:
        """Get file extension."""
        return ".sarif"

    def _create_sarif_document(self, review: SecurityReview) -> Dict[str, Any]:
        """
        Create complete SARIF document.

        Args:
            review: SecurityReview to convert

        Returns:
            SARIF document dictionary
        """
        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "FalconEYE",
                            "version": __version__,
                            "informationUri": "https://github.com/NoAuthZone/FalconEYE-NG",
                            "semanticVersion": __version__,
                            "rules": self._get_sarif_rules(),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": review.started_at.isoformat() if review.started_at else None,
                            "endTimeUtc": review.completed_at.isoformat() if review.completed_at else None,
                        }
                    ],
                    "results": [
                        self._finding_to_sarif_result(finding)
                        for finding in review.findings
                    ],
                }
            ],
        }

    def _finding_to_sarif_result(self, finding: SecurityFinding) -> Dict[str, Any]:
        """
        Convert SecurityFinding to SARIF result.

        Args:
            finding: SecurityFinding to convert

        Returns:
            SARIF result dictionary
        """
        return {
            "ruleId": self._get_rule_id_for_severity(finding.severity),
            "level": self._severity_to_sarif_level(finding.severity),
            "message": {
                "text": finding.issue,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                        },
                        "region": {
                            "startLine": finding.line_start if finding.line_start else 1,
                            "endLine": finding.line_end if finding.line_end else None,
                            "snippet": {
                                "text": finding.code_snippet if finding.code_snippet else "",
                            },
                        },
                    }
                }
            ],
            "properties": {
                "confidence": finding.confidence.value,
                "reasoning": finding.reasoning,
                "mitigation": finding.mitigation,
            },
        }

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """
        Convert FalconEYE severity to SARIF level.

        SARIF levels: error, warning, note, none

        Args:
            severity: FalconEYE severity

        Returns:
            SARIF level string
        """
        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "warning",
            Severity.INFO: "note",
        }
        return severity_map.get(severity, "warning")

    def _get_rule_id_for_severity(self, severity: Severity) -> str:
        """
        Get rule ID based on severity.

        Args:
            severity: Finding severity

        Returns:
            Rule ID string
        """
        return f"falconeye-{severity.value}"

    def _get_sarif_rules(self) -> List[Dict[str, Any]]:
        """
        Get SARIF rule definitions.

        Returns:
            List of SARIF rule dictionaries
        """
        return [
            {
                "id": "falconeye-critical",
                "name": "CriticalSecurityIssue",
                "shortDescription": {
                    "text": "Critical security vulnerability identified by AI analysis"
                },
                "fullDescription": {
                    "text": "A critical security vulnerability that could lead to severe compromise of the system. Immediate remediation is required."
                },
                "defaultConfiguration": {
                    "level": "error"
                },
                "properties": {
                    "tags": ["security", "critical"],
                    "precision": "high",
                },
            },
            {
                "id": "falconeye-high",
                "name": "HighSecurityIssue",
                "shortDescription": {
                    "text": "High severity security vulnerability identified by AI analysis"
                },
                "fullDescription": {
                    "text": "A high severity security vulnerability that should be remediated promptly."
                },
                "defaultConfiguration": {
                    "level": "error"
                },
                "properties": {
                    "tags": ["security", "high"],
                    "precision": "high",
                },
            },
            {
                "id": "falconeye-medium",
                "name": "MediumSecurityIssue",
                "shortDescription": {
                    "text": "Medium severity security vulnerability identified by AI analysis"
                },
                "fullDescription": {
                    "text": "A medium severity security vulnerability that should be addressed."
                },
                "defaultConfiguration": {
                    "level": "warning"
                },
                "properties": {
                    "tags": ["security", "medium"],
                    "precision": "medium",
                },
            },
            {
                "id": "falconeye-low",
                "name": "LowSecurityIssue",
                "shortDescription": {
                    "text": "Low severity security issue identified by AI analysis"
                },
                "fullDescription": {
                    "text": "A low severity security issue that should be reviewed."
                },
                "defaultConfiguration": {
                    "level": "warning"
                },
                "properties": {
                    "tags": ["security", "low"],
                    "precision": "medium",
                },
            },
            {
                "id": "falconeye-info",
                "name": "SecurityInformation",
                "shortDescription": {
                    "text": "Security-related information identified by AI analysis"
                },
                "fullDescription": {
                    "text": "Security-related information that may be of interest."
                },
                "defaultConfiguration": {
                    "level": "note"
                },
                "properties": {
                    "tags": ["security", "info"],
                    "precision": "low",
                },
            },
        ]