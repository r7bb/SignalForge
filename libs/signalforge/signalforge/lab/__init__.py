"""Lab telemetry generation (normal activity plus benign attack-shape simulations)."""

from .generator import SCENARIOS, Scenario, TelemetryGenerator, list_scenarios

__all__ = ["SCENARIOS", "Scenario", "TelemetryGenerator", "list_scenarios"]
