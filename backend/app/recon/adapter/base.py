"""
Recon Adapter - BaseModule Definition
Ported & Adapted from Recon-ng Framework Concepts (Tim Tomes / LaNMaS)
Licensed under GNU General Public License v3.0 (GPL-3.0)

Provides a clean, async, decoupled interface for discovery and vulnerability modules.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
import os

from ...core.config import settings
from ...schemas.schemas import AssetBase, FindingBase

class ModuleMeta(BaseModel):
    name: str
    author: str = "Auditor Security Team"
    description: str
    category: str = "discovery"  # discovery, enrichment, vulnerability, active
    is_passive: bool = True
    version: str = "1.0.0"

class BaseModule(ABC):
    """
    Abstract Base Class for all Auditor discovery and audit modules.
    Replaces Recon-ng's interactive BaseModule with an async, non-blocking service pattern.
    """
    meta: ModuleMeta
    options: Dict[str, Any] = {}
    required_keys: List[str] = []

    def __init__(self, custom_options: Optional[Dict[str, Any]] = None):
        if custom_options:
            self.options = {**self.options, **custom_options}

    def get_api_key(self, key_name: str) -> Optional[str]:
        """
        Retrieves API key from environment or Auditor settings store.
        """
        # First check Settings object
        val = getattr(settings, key_name, None)
        if val:
            return str(val).strip()
        # Fallback to direct os.getenv
        return os.getenv(key_name, None)

    def has_required_keys(self) -> bool:
        """
        Validates whether all required API keys are configured.
        """
        for k in self.required_keys:
            if not self.get_api_key(k):
                return False
        return True

    @abstractmethod
    async def run(self, target: str, context: Any) -> List[Union[AssetBase, FindingBase]]:
        """
        Main execution entry point.
        Takes target domain or IP and runtime ScanContext.
        Returns a list of discovered Assets or Findings.
        """
        pass
