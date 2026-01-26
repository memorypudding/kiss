"""KISS Plugin Registry.

Auto-discovers and manages plugins from built-in and custom locations.
"""

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from .base import APIKeyRequirement, BasePlugin, PluginMetadata
from .async_base import AsyncBasePlugin


class PluginRegistry:
    """Registry for plugin auto-discovery and management.

    Singleton pattern ensures all parts of the application use
    the same plugin registry instance.
    """

    _instance: Optional["PluginRegistry"] = None
    _plugins: Dict[str, Type[BasePlugin]]
    _initialized: bool

    def __new__(cls) -> "PluginRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._plugins = {}
            cls._instance._initialized = False
        return cls._instance

    def discover_plugins(self, custom_paths: Optional[List[Path]] = None) -> None:
        """Auto-discover and register all plugins.

        Args:
            custom_paths: Additional paths to search for plugins
        """
        if self._initialized:
            return

        # 1. Discover built-in plugins
        self._discover_builtin_plugins()

        # 2. Discover custom plugins from provided paths
        if custom_paths:
            for path in custom_paths:
                if path.exists():
                    self._discover_custom_plugins(path)

        # 3. Discover user plugins from ~/.xsint/plugins/
        user_plugin_dir = Path.home() / ".xsint" / "plugins"
        if user_plugin_dir.exists():
            self._discover_custom_plugins(user_plugin_dir)

        self._initialized = True

    def _discover_builtin_plugins(self) -> None:
        """Discover plugins in kiss.plugins subpackages."""
        # Get the plugins package path
        plugins_path = Path(__file__).parent

        # Scan subdirectories for plugin modules
        categories = [
            "breach_detection",
            "ip_intelligence",
            "identity",
            "hash_lookup",
            "phone",
            "username",
            "wifi",
        ]

        for category in categories:
            category_path = plugins_path / category
            if category_path.exists():
                self._discover_plugins_in_directory(category_path, f"kiss.plugins.{category}")

    def _discover_plugins_in_directory(self, path: Path, package_prefix: str) -> None:
        """Discover plugins in a specific directory.

        Args:
            path: Directory path to scan
            package_prefix: Python package prefix for imports
        """
        for py_file in path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            module_name = f"{package_prefix}.{py_file.stem}"

            try:
                module = importlib.import_module(module_name)
                self._register_module_plugins(module)
            except Exception as e:
                # Log but don't fail on individual plugin errors
                print(f"Warning: Could not load plugin {module_name}: {e}")

    def _discover_custom_plugins(self, path: Path) -> None:
        """Discover custom plugins from a directory.

        Args:
            path: Directory containing custom plugin files
        """
        if not path.exists():
            return

        # Add path to sys.path temporarily for imports
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)

        for py_file in path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self._register_module_plugins(module)
            except Exception as e:
                print(f"Warning: Could not load custom plugin {py_file}: {e}")

    def _register_module_plugins(self, module) -> None:
        """Find and register BasePlugin or AsyncBasePlugin subclasses in a module.

        Args:
            module: Python module to scan for plugins
        """
        for name in dir(module):
            obj = getattr(module, name)

            # Check if it's a class that inherits from BasePlugin or AsyncBasePlugin
            if isinstance(obj, type):
                # Check for AsyncBasePlugin first (newer async plugins)
                if (
                    issubclass(obj, AsyncBasePlugin)
                    and obj is not AsyncBasePlugin
                ):
                    self.register(obj)
                # Also check for BasePlugin (older sync plugins)
                elif (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and not issubclass(obj, AsyncBasePlugin)  # Avoid double registration
                ):
                    self.register(obj)

    def register(self, plugin_class: Type[BasePlugin]) -> bool:
        """Register a plugin class.

        Args:
            plugin_class: The plugin class to register

        Returns:
            True if registered successfully
        """
        try:
            metadata = plugin_class.get_metadata()
            self._plugins[metadata.name] = plugin_class
            return True
        except Exception as e:
            print(f"Warning: Could not register plugin {plugin_class}: {e}")
            return False

    def unregister(self, name: str) -> bool:
        """Unregister a plugin by name.

        Args:
            name: Plugin name to unregister

        Returns:
            True if unregistered successfully
        """
        if name in self._plugins:
            del self._plugins[name]
            return True
        return False

    def get(self, name: str) -> Optional[Type[BasePlugin]]:
        """Get a plugin class by name.

        Args:
            name: Plugin name

        Returns:
            Plugin class or None
        """
        return self._plugins.get(name)

    def get_all(self) -> Dict[str, Type[BasePlugin]]:
        """Get all registered plugins.

        Returns:
            Dict of plugin name to plugin class
        """
        return self._plugins.copy()

    def get_by_category(self, category: str) -> List[Type[BasePlugin]]:
        """Get all plugins in a category.

        Args:
            category: Category name (e.g., "Breach Detection")

        Returns:
            List of plugin classes in the category
        """
        return [
            p
            for p in self._plugins.values()
            if p.get_metadata().category.lower() == category.lower()
        ]

    def get_by_scan_type(self, scan_type: str) -> List[Type[BasePlugin]]:
        """Get all plugins that support a scan type.

        Args:
            scan_type: Scan type (e.g., "EMAIL", "IP")

        Returns:
            List of plugin classes supporting the scan type
        """
        scan_type_upper = scan_type.upper()
        return [
            p
            for p in self._plugins.values()
            if scan_type_upper in [s.upper() for s in p.get_metadata().supported_scan_types]
        ]

    def get_categories(self) -> List[str]:
        """Get list of all unique categories.

        Returns:
            List of category names
        """
        categories = set()
        for plugin_class in self._plugins.values():
            categories.add(plugin_class.get_metadata().category)
        return sorted(list(categories))

    def get_all_api_requirements(self) -> Dict[str, List[APIKeyRequirement]]:
        """Get all API key requirements grouped by category.

        Returns:
            Dict of category name to list of APIKeyRequirement
        """
        from collections import defaultdict

        requirements: Dict[str, List[APIKeyRequirement]] = defaultdict(list)

        for plugin_class in self._plugins.values():
            metadata = plugin_class.get_metadata()
            category_name = metadata.category

            for req in metadata.api_key_requirements:
                # Avoid duplicates (same key might be used by multiple plugins)
                existing_keys = [r.key_name for r in requirements[category_name]]
                if req.key_name not in existing_keys:
                    requirements[category_name].append(req)

        return dict(requirements)

    def get_plugins_requiring_keys(self) -> List[Type[BasePlugin]]:
        """Get all plugins that require API keys.

        Returns:
            List of plugin classes with required API keys
        """
        return [
            p
            for p in self._plugins.values()
            if any(req.is_required for req in p.get_metadata().api_key_requirements)
        ]

    def reset(self) -> None:
        """Reset the registry (mainly for testing)."""
        self._plugins = {}
        self._initialized = False

    async def discover_plugins_async(
        self, custom_paths: Optional[List[Path]] = None
    ) -> None:
        """Async version of discover_plugins for use with async engine.

        Plugin discovery is CPU-bound (file I/O and imports), so this
        just wraps the sync version. The async signature allows it to
        be called from async code without blocking warnings.

        Args:
            custom_paths: Additional paths to search for plugins
        """
        # Plugin discovery is mostly synchronous (file scanning, imports)
        # We just call the sync version here
        self.discover_plugins(custom_paths)


# Global registry instance getter
_registry: Optional[PluginRegistry] = None


def get_registry() -> PluginRegistry:
    """Get the global plugin registry instance.

    Returns:
        PluginRegistry singleton instance
    """
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry
