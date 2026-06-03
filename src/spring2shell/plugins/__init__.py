"""
Dynamic plugin loader and registry for spring2shell.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from typing import Type

from spring2shell.plugins.base import BasePlugin

_PLUGINS: dict[str, type[BasePlugin]] = {}


def load_plugins() -> None:
    """Dynamically discover and load plugin subclasses under this package."""
    global _PLUGINS
    _PLUGINS.clear()

    package = sys.modules[__name__]
    # Path is a list of directory paths containing the package modules
    path = package.__path__ if hasattr(package, "__path__") else []
    for _, module_name, _ in pkgutil.walk_packages(path, package.__name__ + "."):
        try:
            mod = importlib.import_module(module_name)
            for _name, attr in vars(mod).items():
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BasePlugin)
                    and attr is not BasePlugin
                ) and attr.name:
                    _PLUGINS[attr.name] = attr
        except Exception:
            pass


def get_plugins() -> dict[str, type[BasePlugin]]:
    """Return dict of registered plugins, loading them first if empty."""
    if not _PLUGINS:
        load_plugins()
    return _PLUGINS
