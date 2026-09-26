"""Security-related domain models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List
from uuid import UUID, uuid4


class Severity(str, Enum):
    """Security finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(str, Enum):
    """AI confidence level in the finding."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class SecurityFinding:
    """
    Immutable value object representing a security finding.

    IMPORTANT: This finding is generated purely by AI analysis,
    not by pattern matching or static analysis rules.
    """
    id: UUID
    issue: str
    reasoning: str
    mitigation: str
    severity: Severity
    confidence: FindingConfidence
    file_path: str
    code_snippet: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    cwe_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        issue: str,
        reasoning: str,
        mitigation: str,
        severity: Severity,
        confidence: FindingConfidence,
        file_path: str,
        code_snippet: str,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        cwe_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> "SecurityFinding":
        """
        Factory method to create a security finding.

        LLM output is not type-safe: models sometimes return code_snippet as a
        list of lines, line numbers as strings ("12" / "12-14"), etc. All
        fields are normalized here so downstream code (location mapping,
        grounding, formatters) never crashes on unexpected types.
        """
        start = cls._to_line(line_start)
        end = cls._to_line(line_end)
        # "12-14" given as line_start -> use it as a range
        if isinstance(line_start, str) and "-" in line_start:
            parts = line_start.split("-", 1)
            range_end = cls._to_line(parts[1])
            if end is None and range_end is not None:
                end = range_end
        return cls(
            id=uuid4(),
            issue=cls._to_text(issue) or "Unknown issue",
            reasoning=cls._to_text(reasoning),
            mitigation=cls._to_text(mitigation),
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            code_snippet=cls._to_text(code_snippet),
            line_start=start,
            line_end=end,
            cwe_id=cls._to_text(cwe_id) or None,
            tags=[cls._to_text(t) for t in tags] if isinstance(tags, list) else (
                [cls._to_text(tags)] if tags else []
            ),
        )

    @staticmethod
    def _to_text(value) -> str:
        """Coerce LLM-provided values to text (list of lines -> joined)."""
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple)):
            return "\n".join(SecurityFinding._to_text(v) for v in value)
        if isinstance(value, dict):
            import json
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    @staticmethod
    def _to_line(value) -> Optional[int]:
        """Coerce a line number (int, float, '12', 'line 12') to int or None."""
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value if value > 0 else None
        if isinstance(value, float):
            return int(value) if value > 0 else None
        if isinstance(value, str):
            import re
            m = re.search(r"\d+", value)
            return int(m.group()) if m and int(m.group()) > 0 else None
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "issue": self.issue,
            "reasoning": self.reasoning,
            "mitigation": self.mitigation,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file_path": self.file_path,
            "code_snippet": self.code_snippet,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "cwe_id": self.cwe_id,
            "tags": self.tags,
        }


@dataclass
class SecurityReview:
    """
    Aggregate root for a security review session.

    Contains all findings from an AI-powered security analysis.
    NO pattern matching involved - purely AI-driven.
    """
    id: UUID
    codebase_path: str
    language: str
    started_at: datetime
    findings: List[SecurityFinding] = field(default_factory=list)
    completed_at: Optional[datetime] = None
    files_analyzed: int = 0

    @classmethod
    def create(cls, codebase_path: str, language: str) -> "SecurityReview":
        """Factory method to create a new security review."""
        return cls(
            id=uuid4(),
            codebase_path=codebase_path,
            language=language,
            started_at=datetime.now(timezone.utc),
        )

    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a security finding to the review."""
        self.findings.append(finding)

    def complete(self) -> None:
        """Mark the review as completed."""
        self.completed_at = datetime.now(timezone.utc)

    def get_findings_by_severity(self, severity: Severity) -> List[SecurityFinding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_count(self) -> int:
        """Count critical findings."""
        return len(self.get_findings_by_severity(Severity.CRITICAL))

    def get_high_count(self) -> int:
        """Count high severity findings."""
        return len(self.get_findings_by_severity(Severity.HIGH))

    def get_medium_count(self) -> int:
        """Count medium severity findings."""
        return len(self.get_findings_by_severity(Severity.MEDIUM))

    def get_low_count(self) -> int:
        """Count low severity findings."""
        return len(self.get_findings_by_severity(Severity.LOW))

    def get_all_languages(self) -> List[str]:
        """
        Get all unique languages from analyzed files.
        
        Extracts languages from file paths in findings by checking file extensions.
        Returns list sorted by frequency (most common first).
        
        Returns:
            List of unique language names
        """
        from collections import Counter
        from pathlib import Path
        
        from ..services.language_detector import LanguageDetector

        # Single source of truth for extension -> language
        EXTENSION_TO_LANGUAGE = LanguageDetector.EXTENSION_TO_LANGUAGE
        
        # Count languages from file paths in findings
        language_counts = Counter()
        for finding in self.findings:
            if finding.file_path:
                ext = Path(finding.file_path).suffix.lower()
                if ext in EXTENSION_TO_LANGUAGE:
                    language_counts[EXTENSION_TO_LANGUAGE[ext]] += 1
        
        # If no languages found from findings, return the primary language
        if not language_counts:
            return [self.language]
        
        # Sort by count (descending) and return language names
        sorted_languages = [lang for lang, _ in language_counts.most_common()]
        return sorted_languages

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "codebase_path": self.codebase_path,
            "language": self.language,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "files_analyzed": self.files_analyzed,
            "total_findings": len(self.findings),
            "critical": self.get_critical_count(),
            "high": self.get_high_count(),
            "medium": len(self.get_findings_by_severity(Severity.MEDIUM)),
            "low": len(self.get_findings_by_severity(Severity.LOW)),
            "findings": [f.to_dict() for f in self.findings],
        }