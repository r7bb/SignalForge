"""Detection engine and its window state."""

from .engine import DetectionEngine, EngineStats
from .state import SlidingWindow, SuppressionCache, WindowEntry, WindowStore

__all__ = [
    "DetectionEngine",
    "EngineStats",
    "SlidingWindow",
    "SuppressionCache",
    "WindowEntry",
    "WindowStore",
]
