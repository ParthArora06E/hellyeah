"""
Drop-in Plugin Loader and Dynamic Discovery System
Discovers and loads any module in plugins/ implementing BaseModule.
"""
import os
import sys
import importlib.util
from typing import Dict, List, Type, Any
from .base import BaseModule

_LOADED_PLUGINS: Dict[str, Type[BaseModule]] = {}

def get_plugins_directory() -> str:
    # Look for top-level plugins/ or backend/plugins/
    top_plugins = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "plugins"))
    if os.path.isdir(top_plugins):
        return top_plugins
    return os.path.abspath("plugins")

def discover_plugins() -> Dict[str, Dict[str, Any]]:
    """
    Scans plugins/ directory, imports modules, and registers valid BaseModule subclasses.
    """
    global _LOADED_PLUGINS
    _LOADED_PLUGINS.clear()
    
    plugins_dir = get_plugins_directory()
    registry = {}

    if not os.path.exists(plugins_dir):
        os.makedirs(plugins_dir, exist_ok=True)
        return registry

    for fname in os.listdir(plugins_dir):
        if fname.endswith(".py") and not fname.startswith("__"):
            plugin_path = os.path.join(plugins_dir, fname)
            module_name = f"auditor_plugin_{fname[:-3]}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, plugin_path)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = mod
                    spec.loader.exec_module(mod)

                    for attr_name in dir(mod):
                        cls = getattr(mod, attr_name)
                        if isinstance(cls, type) and issubclass(cls, BaseModule) and cls is not BaseModule:
                            meta = getattr(cls, "meta", None)
                            p_name = meta.name if meta else fname[:-3]
                            _LOADED_PLUGINS[p_name] = cls
                            registry[p_name] = {
                                "name": p_name,
                                "author": meta.author if meta else "Custom",
                                "description": meta.description if meta else "Custom user-supplied plugin",
                                "category": meta.category if meta else "custom",
                                "is_passive": meta.is_passive if meta else True,
                                "file": fname,
                                "has_keys": cls().has_required_keys()
                            }
            except Exception as e:
                registry[fname[:-3]] = {
                    "name": fname[:-3],
                    "error": str(e),
                    "file": fname
                }

    return registry

async def execute_all_plugins(target: str, context: Any) -> List[Any]:
    """
    Runs all successfully loaded drop-in plugins against target.
    """
    discover_plugins()
    results = []
    for name, cls in _LOADED_PLUGINS.items():
        try:
            instance = cls()
            if not instance.has_required_keys():
                context.emit_log("info", f"Plugin '{name}' skipped (missing required API keys).")
                continue
            context.emit_log("info", f"Executing drop-in plugin: {name}...")
            res = await instance.run(target, context)
            if res:
                results.extend(res)
            context.emit_log("good", f"Plugin '{name}' completed successfully.")
        except Exception as e:
            context.emit_log("warn", f"Plugin '{name}' failed with error: {e}")
    return results
