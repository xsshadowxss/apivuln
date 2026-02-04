"""
APIVuln Detection Modules

This package contains all vulnerability detection modules.
Each module focuses on a specific class of vulnerability.
"""

from .base import BaseModule, Finding, Severity
from .bola import BOLAModule
from .bfla import BFLAModule
from .jwt import JWTModule
from .injection import InjectionModule
from .rate_limit import RateLimitModule
from .mass_assign import MassAssignmentModule
from .disclosure import DisclosureModule
from .xss import XSSModule
from .cors import CORSModule
from .headers import HeadersModule

# Registry of all available modules
MODULES = [
    BOLAModule,
    BFLAModule,
    JWTModule,
    InjectionModule,
    RateLimitModule,
    MassAssignmentModule,
    DisclosureModule,
    XSSModule,
    CORSModule,
    HeadersModule,
]

# Module name to class mapping
MODULE_MAP = {module.name: module for module in MODULES}


def get_module(name: str):
    """Get a module class by name."""
    return MODULE_MAP.get(name)


def get_all_module_names() -> list[str]:
    """Get list of all available module names."""
    return list(MODULE_MAP.keys())


def get_module_info() -> list[dict]:
    """Get information about all modules."""
    return [
        {
            "name": module.name,
            "description": module.description,
            "version": module.version,
        }
        for module in MODULES
    ]


__all__ = [
    # Base classes
    "BaseModule",
    "Finding", 
    "Severity",
    # Registry
    "MODULES",
    "MODULE_MAP",
    # Functions
    "get_module",
    "get_all_module_names",
    "get_module_info",
    # Module classes
    "BOLAModule",
    "BFLAModule",
    "JWTModule",
    "InjectionModule",
    "RateLimitModule",
    "MassAssignmentModule",
    "DisclosureModule",
    "XSSModule",
    "CORSModule",
    "HeadersModule",
]
