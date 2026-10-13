"""
Root module alias for core.rotator
Allows: from core.rotator import rotator
"""
from backend.app.core.rotator import rotator, IPRotator

__all__ = ["rotator", "IPRotator"]
