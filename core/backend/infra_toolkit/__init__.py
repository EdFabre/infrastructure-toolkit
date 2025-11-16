"""
Infrastructure Toolkit

Standardized CLI toolkit for infrastructure management with built-in safety mechanisms.
"""

__version__ = "1.0.0"
__author__ = "Claude Code"
__description__ = "Standardized infrastructure management toolkit"

from .base_tool import BaseTool
from .cli import main

__all__ = ["BaseTool", "main", "__version__"]
