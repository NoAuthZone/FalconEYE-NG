"""Review single file command and handler."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable
import time

from ...domain.models.security import SecurityReview, SecurityFinding
from ...domain.services.security_analyzer import SecurityAnalyzer
from ...domain.services.context_assembler import ContextAssembler
from ...infrastructure.logging import FalconEyeLogger


@dataclass
class ReviewFileCommand:
    """
    Command to review a single file.

    Uses AI to analyze the file for security vulnerabilities.
    NO pattern matching - pure AI reasoning.
    """
    file_path: Path
    language: str
    system_prompt: str
    validate_findings: bool = False
    top_k_context: int = 5
    stream_callback: Optional[Callable[[str], None]] = None
    finding_callback: Optional[Callable[['SecurityFinding'], None]] = None


class ReviewFileHandler:
    """
    Handler for review file command.

    Orchestrates:
    1. Read file content
    2. Assemble context with RAG
    3. AI analysis
    4. Optional validation
    """

    def __init__(
        self,
        security_analyzer: SecurityAnalyzer,
        context_assembler: ContextAssembler,
    ):
        """
        Initialize handler.

        Args:
            security_analyzer: AI-powered security analyzer
            context_assembler: Context assembly for RAG
        """
        self.security_analyzer = security_analyzer
        self.context_assembler = context_assembler
        self.logger = FalconEyeLogger.get_instance()

    async def handle(self, command: ReviewFileCommand) -> SecurityReview:
        """
        Execute review file command.

        Args:
            command: Review command

        Returns:
            SecurityReview with AI-identified findings
        """
        start_time = time.time()

        # Log start
        self.logger.info(
            "Starting file review",
            extra={
                "file_path": str(command.file_path),
                "language": command.language,
                "validate_findings": command.validate_findings,
                "top_k_context": command.top_k_context,
            }
        )

        # Read file
        content = command.file_path.read_text(encoding="utf-8-sig", errors="replace")

        # Create review session
        review = SecurityReview.create(
            codebase_path=str(command.file_path),
            language=command.language,
        )

        # Assemble context with RAG
        context = await self.context_assembler.assemble_context(
            file_path=str(command.file_path),
            code_snippet=content,
            language=command.language,
            top_k_similar=command.top_k_context,
            analysis_type="review",
        )

        # AI analysis
        findings = await self.security_analyzer.analyze_code(
            context=context,
            system_prompt=command.system_prompt,
            stream_callback=command.stream_callback,
            finding_callback=command.finding_callback,
        )

        # Add findings to review
        for finding in findings:
            review.add_finding(finding)

        # Optional validation
        if command.validate_findings and findings:
            self.logger.info(
                "Validating findings with AI",
                extra={
                    "file_path": str(command.file_path),
                    "findings_count": len(findings),
                }
            )

            validated_findings = await self.security_analyzer.validate_findings(
                findings=findings,
                context=context,
            )

            # Replace with validated
            review.findings = validated_findings

        review.files_analyzed = 1
        review.complete()

        # Calculate duration
        duration = time.time() - start_time

        # Log completion
        self.logger.info(
            "File review completed",
            extra={
                "file_path": str(command.file_path),
                "findings_count": len(review.findings),
                "validated": command.validate_findings,
                "duration_seconds": round(duration, 2),
            }
        )

        return review