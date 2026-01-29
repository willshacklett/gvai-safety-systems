"""
GV Runtime Guard

A lightweight runtime guard that computes a GV risk signal from
agent/tool-loop telemetry.
"""

from .guard import GVRuntimeGuard, GuardConfig
from .signals import RuntimeSignals

__all__ = ["GVRuntimeGuard", "GuardConfig", "RuntimeSignals"]
