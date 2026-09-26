"""LLM service interface (Port)."""

from abc import ABC, abstractmethod
from typing import List, Optional, Callable
from ..models.prompt import PromptContext


class LLMService(ABC):
    """
    Port for LLM operations.

    This is the PRIMARY interface for AI-powered analysis.
    ALL security findings come from the LLM, NOT from pattern matching.

    Implementations provide different LLM backends (Ollama, etc.)
    """

    @abstractmethod
    async def analyze_code_security(
        self,
        context: PromptContext,
        system_prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """
        Analyze code for security vulnerabilities using AI.

        This is the core method that performs AI-powered security analysis.
        NO pattern matching - pure LLM reasoning.

        Args:
            context: Full context for AI analysis
            system_prompt: System instructions for the AI
            stream_callback: Optional callback to receive streaming tokens

        Returns:
            Raw AI response (usually JSON with findings)
        """
        pass

    @abstractmethod
    async def generate_embedding(
        self,
        text: str,
    ) -> List[float]:
        """
        Generate embedding vector for text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        pass

    @abstractmethod
    async def generate_embeddings_batch(
        self,
        texts: List[str],
    ) -> List[List[float]]:
        """
        Generate embeddings for multiple texts (batch operation).

        Args:
            texts: List of texts to embed

        Returns:
            List of embedding vectors
        """
        pass

    @abstractmethod
    async def validate_findings(
        self,
        code_snippet: str,
        findings: str,
        context: str,
    ) -> str:
        """
        Use AI to validate security findings and remove false positives.

        The AI evaluates whether findings are genuine security issues.
        NO pattern matching involved.

        Args:
            code_snippet: Original code
            findings: Initial findings from analysis
            context: Additional context

        Returns:
            Validated findings (filtered by AI)
        """
        pass

    @abstractmethod
    async def summarize_findings(
        self,
        findings: List[str],
    ) -> str:
        """
        Use AI to summarize multiple findings.

        Args:
            findings: List of finding descriptions

        Returns:
            Summary of findings
        """
        pass

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """
        Count tokens in text for the current model.

        Args:
            text: Text to count tokens for

        Returns:
            Number of tokens
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if LLM service is available.

        Returns:
            True if service is healthy
        """
        pass