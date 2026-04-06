# backend/modules/__init__.py
"""SentinelCTF modular backend package.

Each submodule (forensics, crypto, osint, web, reversing, pwn, misc) provides:
- `CATEGORY` – human readable category name
- `TOOLS` – list of allowed command-line tools for that category
- `system_prompt()` – returns a tailored system prompt for the LLM
- `suggest_commands(challenge_text: str, filename: Optional[str]) -> List[str]`

The registry maps category names to module objects for easy lookup.
"""

from importlib import import_module
from typing import Dict, Any, Optional

MODULE_NAMES = [
    "forensics",
    "crypto",
    "osint",
    "web",
    "reversing",
    "pwn",
    "misc",
]

registry: Dict[str, Any] = {}

for _name in MODULE_NAMES:
    try:
        _mod = import_module(f".{_name}", package=__name__)
        if hasattr(_mod, "CATEGORY"):
            registry[_mod.CATEGORY.lower()] = _mod
    except ImportError:
        pass  # gracefully skip unavailable modules

def get_module_by_category(category: str) -> Optional[Any]:
    """Return the module matching the given category (case-insensitive)."""
    return registry.get(category.lower())

def get_all_allowed_tools() -> list:
    """Aggregate every allowed tool across all registered modules."""
    tools = set()
    for mod in registry.values():
        if hasattr(mod, "TOOLS"):
            tools.update(mod.TOOLS)
    return sorted(tools)

def list_categories() -> list:
    """Return sorted list of registered category names."""
    return sorted(registry.keys())
