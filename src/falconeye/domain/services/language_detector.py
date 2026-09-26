"""Language detection domain service."""

import fnmatch
import os
from pathlib import Path
from typing import Dict, Iterable, Optional, List
from collections import Counter
from ..exceptions import LanguageDetectionError


class LanguageDetector:
    """
    Domain service for detecting the primary language of a codebase.

    Uses file extension analysis and intelligent heuristics.
    NO pattern matching for vulnerabilities - just language detection.
    """

    # Language to extensions mapping
    LANGUAGE_EXTENSIONS = {
        "c": [".c", ".h"],
        "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hh"],
        "python": [".py"],
        "rust": [".rs"],
        "go": [".go"],
        "php": [".php"],
        "java": [".java"],
        "dart": [".dart"],
        "javascript": [".js", ".jsx", ".mjs", ".cjs"],
        "typescript": [".ts", ".tsx", ".mts", ".cts"],
        "ruby": [".rb", ".rake"],
    }

    # Extensions to language mapping (reverse)
    EXTENSION_TO_LANGUAGE = {
        ext: lang
        for lang, exts in LANGUAGE_EXTENSIONS.items()
        for ext in exts
    }

    # Directories to skip during detection
    SKIP_DIRS = {
        "node_modules", "__pycache__", "venv", ".venv", "env",
        "build", "dist", "target", ".git", ".svn", "vendor",
        ".dart_tool", "Pods", "DerivedData",
    }

    # File patterns to skip
    SKIP_PATTERNS = {".pyc", ".class", ".o", ".so", ".dylib"}

    def detect_language(
        self,
        codebase_path: Path,
        force_language: Optional[str] = None,
    ) -> str:
        """
        Detect the primary language of a codebase or single file.

        Args:
            codebase_path: Root path of codebase or single file
            force_language: Force specific language (skip detection)

        Returns:
            Primary language name

        Raises:
            LanguageDetectionError: If detection fails
        """
        if force_language:
            if not self._is_valid_language(force_language):
                raise LanguageDetectionError(
                    f"Unsupported language: {force_language}"
                )
            return force_language

        # If single file, detect from extension
        if codebase_path.is_file():
            extension = codebase_path.suffix.lower()
            language = self.EXTENSION_TO_LANGUAGE.get(extension)
            if not language:
                raise LanguageDetectionError(
                    f"Unsupported file type: {extension}"
                )
            return language

        # Count files by language (for directories)
        language_counts = self._count_files_by_language(codebase_path)

        if not language_counts:
            raise LanguageDetectionError(
                f"No supported source files found in {codebase_path}"
            )

        # Determine primary language
        primary_language = self._determine_primary_language(language_counts)

        return primary_language

    def _count_files_by_language(self, root_path: Path) -> Dict[str, int]:
        """
        Count source files by language.

        Args:
            root_path: Root directory to scan

        Returns:
            Dictionary mapping language to file count
        """
        language_counts: Counter = Counter()

        for file_path in self._walk_codebase(root_path):
            extension = file_path.suffix.lower()
            if language := self.EXTENSION_TO_LANGUAGE.get(extension):
                language_counts[language] += 1

        return dict(language_counts)

    def _walk_codebase(self, root_path: Path):
        """
        Walk codebase and yield source files.

        Skips common non-source directories and files.

        Args:
            root_path: Root directory

        Yields:
            Path objects for source files
        """
        yield from self.discover_source_files(root_path)

    # ------------------------------------------------------------------
    # File discovery (single source of truth for index/review/scan)
    # ------------------------------------------------------------------

    @staticmethod
    def _has_glob(pattern: str) -> bool:
        return any(ch in pattern for ch in "*?[")

    @classmethod
    def is_excluded(cls, relative_posix: str, patterns: Iterable[str]) -> bool:
        """
        Check a path (relative to the scan root, '/'-separated) against
        exclusion patterns.

        - Glob patterns (``*/node_modules/*``, ``*.min.js``) are matched with
          fnmatch against the relative path, also with a leading '/' so that
          ``*/dist/*`` matches a top-level ``dist/`` directory.
        - Plain strings keep the old behaviour: substring match.

        Only the path *below* the scan root is considered, so a project that
        itself lives in e.g. ``~/build/app`` is not excluded entirely, and the
        matching works identically on Windows and POSIX.
        """
        rel = relative_posix.lstrip("/")
        rooted = "/" + rel
        for raw in patterns or []:
            pattern = raw.replace("\\", "/").strip()
            if not pattern:
                continue
            if cls._has_glob(pattern):
                # '**/' is equivalent to '*/' for fnmatch ('*' spans '/')
                pattern = pattern.replace("**", "*")
                if fnmatch.fnmatchcase(rel, pattern) or fnmatch.fnmatchcase(rooted, pattern):
                    return True
            elif pattern in rel or pattern in rooted:
                return True
        return False

    def discover_source_files(
        self,
        root_path: Path,
        excluded_patterns: Optional[Iterable[str]] = None,
        languages: Optional[Iterable[str]] = None,
    ) -> List[Path]:
        """
        Discover source files below ``root_path``.

        Uses ``os.walk`` and prunes skipped/hidden directories *before*
        descending, so large trees like ``node_modules`` or ``.git`` are never
        traversed. Result is sorted for deterministic processing order.

        Args:
            root_path: Directory (or single file) to scan
            excluded_patterns: Optional exclusion patterns (see is_excluded)
            languages: Restrict to these languages (default: all supported)

        Returns:
            Sorted list of source file paths
        """
        root_path = Path(root_path)
        if root_path.is_file():
            ext = root_path.suffix.lower()
            return [root_path] if ext in self.EXTENSION_TO_LANGUAGE else []

        if languages is None:
            allowed_exts = set(self.EXTENSION_TO_LANGUAGE)
        else:
            allowed_exts = {
                ext
                for lang in languages
                for ext in self.LANGUAGE_EXTENSIONS.get(lang, [])
            }

        patterns = list(excluded_patterns or [])
        results: List[Path] = []

        for dirpath, dirnames, filenames in os.walk(root_path):
            current = Path(dirpath)
            rel_dir = current.relative_to(root_path).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir

            # Prune directories in-place (never descend into them)
            kept = []
            for d in dirnames:
                if d in self.SKIP_DIRS or d.startswith("."):
                    continue
                rel_sub = f"{rel_dir}/{d}" if rel_dir else d
                if patterns and self.is_excluded(rel_sub + "/", patterns):
                    continue
                kept.append(d)
            dirnames[:] = sorted(kept)

            for name in filenames:
                if name.startswith("."):
                    continue
                if any(name.endswith(p) for p in self.SKIP_PATTERNS):
                    continue
                if Path(name).suffix.lower() not in allowed_exts:
                    continue
                rel_file = f"{rel_dir}/{name}" if rel_dir else name
                if patterns and self.is_excluded(rel_file, patterns):
                    continue
                results.append(current / name)

        results.sort()
        return results

    def _determine_primary_language(
        self,
        language_counts: Dict[str, int],
    ) -> str:
        """
        Determine primary language from counts.

        Applies intelligent heuristics for mixed-language projects.

        Args:
            language_counts: Language to file count mapping

        Returns:
            Primary language name
        """
        if not language_counts:
            raise LanguageDetectionError("No languages detected")

        # Sort by count
        sorted_languages = sorted(
            language_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        primary_lang, primary_count = sorted_languages[0]
        total_files = sum(language_counts.values())
        primary_percentage = (primary_count / total_files) * 100

        # If clearly dominant (>60%), use it
        if primary_percentage > 60:
            return primary_lang

        # Mixed-language project - apply heuristics
        return self._apply_mixed_language_heuristics(
            sorted_languages,
            total_files,
        )

    def _apply_mixed_language_heuristics(
        self,
        sorted_languages: list,
        total_files: int,
    ) -> str:
        """
        Apply heuristics for mixed-language projects.

        Args:
            sorted_languages: Languages sorted by file count
            total_files: Total number of files

        Returns:
            Selected primary language
        """
        languages = {lang: count for lang, count in sorted_languages}

        # C/Rust mix - prefer Rust (more modern)
        if "c" in languages and "rust" in languages:
            return "rust"

        # Dart with significant presence - likely Flutter
        if "dart" in languages:
            dart_percentage = (languages["dart"] / total_files) * 100
            if dart_percentage > 20:
                return "dart"

        # Python with significant presence
        if "python" in languages:
            python_percentage = (languages["python"] / total_files) * 100
            if python_percentage > 25:
                return "python"

        # JavaScript/TypeScript - prefer TypeScript if present
        if "typescript" in languages and "javascript" in languages:
            return "typescript"

        # Default to most common
        return sorted_languages[0][0]

    def _is_valid_language(self, language: str) -> bool:
        """
        Check if language is supported.

        Args:
            language: Language name

        Returns:
            True if supported
        """
        return language.lower() in self.LANGUAGE_EXTENSIONS

    def get_supported_languages(self) -> list[str]:
        """
        Get list of supported languages.

        Returns:
            List of language names
        """
        return list(self.LANGUAGE_EXTENSIONS.keys())

    def detect_all_languages(
        self,
        codebase_path: Path,
        min_file_threshold: int = 1,
    ) -> List[str]:
        """
        Detect all languages present in a codebase.

        This method identifies ALL languages with files in the codebase,
        not just the primary one. Useful for multi-language projects.

        Args:
            codebase_path: Root path of codebase
            min_file_threshold: Minimum number of files required to include a language

        Returns:
            List of language names sorted by file count (descending)

        Raises:
            LanguageDetectionError: If no supported files found
        """
        # If single file, return its language
        if codebase_path.is_file():
            extension = codebase_path.suffix.lower()
            language = self.EXTENSION_TO_LANGUAGE.get(extension)
            if not language:
                raise LanguageDetectionError(
                    f"Unsupported file type: {extension}"
                )
            return [language]

        # Count files by language
        language_counts = self._count_files_by_language(codebase_path)

        if not language_counts:
            raise LanguageDetectionError(
                f"No supported source files found in {codebase_path}"
            )

        # Filter by threshold and sort by count
        filtered_languages = [
            lang for lang, count in language_counts.items()
            if count >= min_file_threshold
        ]

        # Sort by file count (descending)
        sorted_languages = sorted(
            filtered_languages,
            key=lambda lang: language_counts[lang],
            reverse=True,
        )

        return sorted_languages