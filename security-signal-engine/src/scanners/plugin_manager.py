"""
Plugin Manager — dynamic scanner plugin loader.

Solves the technical limitation found in Caido where the extension
ecosystem is immature, and Burp's requires Java. This provides a
Python-native plugin system that allows custom scanner extensions
to be loaded from a plugins/ directory.

Strategy:
  - Auto-discovers Python files in a configurable plugins directory.
  - Each plugin must define a class that extends BaseScanner.
  - Validates plugins before registration (must have name, run method).
  - Logs all discovery and registration events for debugging.
  - Plugins can be enabled/disabled via configuration.

Usage:
  Place a Python file in `plugins/` that defines a class extending
  BaseScanner. Example:

      # plugins/my_custom_scanner.py
      from src.scanners.base import BaseScanner
      from src.models.schemas import RawFinding

      class MyCustomScanner(BaseScanner):
          name = "my-custom-scanner"

          def run(self, target: str) -> list[RawFinding]:
              # Your scanning logic here
              return []
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from typing import Optional

from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Default plugin directory relative to project root
DEFAULT_PLUGIN_DIR = "plugins"


class PluginLoadError(Exception):
    """Raised when a plugin fails to load."""

    def __init__(self, plugin_path: str, message: str):
        self.plugin_path = plugin_path
        super().__init__(f"Failed to load plugin '{plugin_path}': {message}")


class PluginManager:
    """
    Dynamic scanner plugin loader and manager.

    Discovers, validates, and loads Python-based scanner plugins
    from a configurable directory.
    """

    def __init__(
        self,
        plugin_dir: str = DEFAULT_PLUGIN_DIR,
        enabled_plugins: list[str] | None = None,
        disabled_plugins: list[str] | None = None,
    ):
        """
        Args:
            plugin_dir: Path to the plugins directory.
            enabled_plugins: If set, only load these plugin names.
                If None, all discovered plugins are loaded.
            disabled_plugins: Plugin names to skip even if discovered.
        """
        self._plugin_dir = Path(plugin_dir)
        self._enabled_plugins = set(enabled_plugins) if enabled_plugins else None
        self._disabled_plugins = set(disabled_plugins) if disabled_plugins else set()
        self._loaded: dict[str, BaseScanner] = {}
        self._errors: list[str] = []

    @property
    def loaded_plugins(self) -> dict[str, BaseScanner]:
        """Get all successfully loaded plugin instances."""
        return dict(self._loaded)

    @property
    def load_errors(self) -> list[str]:
        """Get error messages from failed plugin loads."""
        return list(self._errors)

    def discover_and_load(self) -> list[BaseScanner]:
        """
        Discover and load all valid plugins from the plugin directory.

        Returns:
            List of successfully loaded scanner instances.
        """
        self._loaded.clear()
        self._errors.clear()

        if not self._plugin_dir.exists():
            logger.info(
                "Plugin directory '%s' not found — no plugins loaded.",
                self._plugin_dir,
            )
            return []

        if not self._plugin_dir.is_dir():
            logger.warning(
                "Plugin path '%s' is not a directory — skipping.",
                self._plugin_dir,
            )
            return []

        # Discover Python files
        plugin_files = sorted(self._plugin_dir.glob("*.py"))
        if not plugin_files:
            logger.info(
                "No plugin files found in '%s'.", self._plugin_dir
            )
            return []

        logger.info(
            "Discovering plugins in '%s': found %d files",
            self._plugin_dir,
            len(plugin_files),
        )

        for plugin_file in plugin_files:
            if plugin_file.name.startswith("_"):
                continue  # Skip __init__.py, __pycache__, etc.

            try:
                scanner = self._load_plugin(plugin_file)
                if scanner:
                    if scanner.name in self._disabled_plugins:
                        logger.info(
                            "Plugin '%s' is disabled — skipping.",
                            scanner.name,
                        )
                        continue

                    if (
                        self._enabled_plugins is not None
                        and scanner.name not in self._enabled_plugins
                    ):
                        logger.debug(
                            "Plugin '%s' not in enabled list — skipping.",
                            scanner.name,
                        )
                        continue

                    self._loaded[scanner.name] = scanner
                    logger.info(
                        "✅ Plugin '%s' loaded from %s",
                        scanner.name,
                        plugin_file.name,
                    )
            except PluginLoadError as e:
                self._errors.append(str(e))
                logger.warning(str(e))
            except Exception as e:
                error_msg = f"Unexpected error loading plugin '{plugin_file}': {e}"
                self._errors.append(error_msg)
                logger.warning(error_msg)

        logger.info(
            "Plugin loading complete: %d loaded, %d errors",
            len(self._loaded),
            len(self._errors),
        )

        return list(self._loaded.values())

    def _load_plugin(self, plugin_path: Path) -> Optional[BaseScanner]:
        """
        Load a single plugin file and return a scanner instance.

        The file must contain exactly one class that extends BaseScanner.
        """
        module_name = f"sse_plugin_{plugin_path.stem}"

        try:
            spec = importlib.util.spec_from_file_location(
                module_name, str(plugin_path)
            )
            if spec is None or spec.loader is None:
                raise PluginLoadError(
                    str(plugin_path), "Could not create module spec"
                )

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

        except Exception as e:
            raise PluginLoadError(
                str(plugin_path), f"Import failed: {e}"
            )

        # Find BaseScanner subclasses in the module
        scanner_classes = []
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseScanner)
                and obj is not BaseScanner
                and obj.__module__ == module_name
            ):
                scanner_classes.append(obj)

        if not scanner_classes:
            raise PluginLoadError(
                str(plugin_path),
                "No BaseScanner subclass found. "
                "Plugin must define a class extending BaseScanner.",
            )

        if len(scanner_classes) > 1:
            logger.warning(
                "Plugin '%s' defines %d scanner classes — using first: %s",
                plugin_path.name,
                len(scanner_classes),
                scanner_classes[0].__name__,
            )

        scanner_cls = scanner_classes[0]

        # Validate the scanner class
        self._validate_scanner_class(scanner_cls, plugin_path)

        # Instantiate
        try:
            instance = scanner_cls()
        except Exception as e:
            raise PluginLoadError(
                str(plugin_path),
                f"Failed to instantiate {scanner_cls.__name__}: {e}",
            )

        return instance

    def _validate_scanner_class(
        self, cls: type, plugin_path: Path
    ) -> None:
        """Validate that a scanner class has required attributes."""
        if not hasattr(cls, "name") or cls.name == "base":
            raise PluginLoadError(
                str(plugin_path),
                f"Scanner class '{cls.__name__}' must define a unique "
                f"'name' attribute (not 'base').",
            )

        if not hasattr(cls, "run"):
            raise PluginLoadError(
                str(plugin_path),
                f"Scanner class '{cls.__name__}' must implement 'run()'.",
            )

    def get_plugin(self, name: str) -> Optional[BaseScanner]:
        """Get a loaded plugin by name."""
        return self._loaded.get(name)

    def get_plugin_names(self) -> list[str]:
        """Get names of all loaded plugins."""
        return list(self._loaded.keys())
