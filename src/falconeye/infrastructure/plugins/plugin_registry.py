"""Plugin registry for managing language plugins."""

from typing import Dict, Optional, List
from .base_plugin import LanguagePlugin
from .python_plugin import PythonPlugin
from .javascript_plugin import JavaScriptPlugin
from .go_plugin import GoPlugin
from .rust_plugin import RustPlugin
from .c_cpp_plugin import CCppPlugin
from .java_plugin import JavaPlugin
from .dart_plugin import DartPlugin
from .php_plugin import PHPPlugin
from .ruby_plugin import RubyPlugin


class PluginRegistry:
    """
    Registry for language plugins.

    Manages loading and accessing language-specific plugins.
    """

    def __init__(self):
        """Initialize empty plugin registry."""
        self._plugins: Dict[str, LanguagePlugin] = {}
        self._extension_map: Dict[str, str] = {}

    def register(self, plugin: LanguagePlugin) -> None:
        """
        Register a language plugin.

        Args:
            plugin: Language plugin to register
        """
        language_name = plugin.language_name
        self._plugins[language_name] = plugin

        # Map file extensions to language
        for ext in plugin.file_extensions:
            self._extension_map[ext] = language_name

    def get_plugin(self, language: str) -> Optional[LanguagePlugin]:
        """
        Get plugin for a language.

        Args:
            language: Language name

        Returns:
            Language plugin or None if not found
        """
        return self._plugins.get(language)

    def get_plugin_by_extension(self, extension: str) -> Optional[LanguagePlugin]:
        """
        Get plugin by file extension.

        Args:
            extension: File extension (e.g., ".py")

        Returns:
            Language plugin or None if not found
        """
        language = self._extension_map.get(extension)
        if language:
            return self._plugins.get(language)
        return None

    def get_all_plugins(self) -> List[LanguagePlugin]:
        """
        Get all registered plugins.

        Returns:
            List of all plugins
        """
        return list(self._plugins.values())

    def get_supported_languages(self) -> List[str]:
        """
        Get list of supported language names.

        Returns:
            List of language names
        """
        return list(self._plugins.keys())

    def get_supported_extensions(self) -> List[str]:
        """
        Get list of supported file extensions.

        Returns:
            List of file extensions
        """
        return list(self._extension_map.keys())

    def is_language_supported(self, language: str) -> bool:
        """
        Check if a language is supported.

        Args:
            language: Language name

        Returns:
            True if language is supported
        """
        return language in self._plugins

    def is_extension_supported(self, extension: str) -> bool:
        """
        Check if a file extension is supported.

        Args:
            extension: File extension

        Returns:
            True if extension is supported
        """
        return extension in self._extension_map

    def load_all_plugins(self) -> None:
        """
        Load all built-in plugins.

        This method registers all available language plugins.
        """
        # Register Python plugin
        self.register(PythonPlugin())

        # Register JavaScript/TypeScript plugin
        js_plugin = JavaScriptPlugin()
        self.register(js_plugin)
        # LanguageDetector reports .ts/.tsx/.mts/.cts as "typescript";
        # without this alias get_plugin("typescript") returns None and
        # TypeScript files fall back to the generic prompt.
        self._plugins["typescript"] = js_plugin

        # Register Go plugin
        self.register(GoPlugin())

        # Register Rust plugin
        self.register(RustPlugin())

        # Register C/C++ plugin
        self.register(CCppPlugin())

        # Register Java plugin
        self.register(JavaPlugin())

        # Register Dart plugin
        self.register(DartPlugin())

        # Register PHP plugin
        self.register(PHPPlugin())

        # Register Ruby plugin
        self.register(RubyPlugin())

    def __repr__(self) -> str:
        """String representation."""
        return f"<PluginRegistry: {len(self._plugins)} plugins loaded>"

    def __str__(self) -> str:
        """String representation."""
        languages = ", ".join(self.get_supported_languages())
        return f"PluginRegistry({languages})"