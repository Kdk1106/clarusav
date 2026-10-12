"""Confidence gating and decision engine for ClarusAV."""

from clarusav.gate.engine import (
    BandPosition,
    ConfidenceGate,
    EscalationCurvePoint,
    GateDecision,
    ThresholdSearchResult,
    Verdict,
)

__all__ = [
    "BandPosition",
    "Verdict",
    "GateDecision",
    "EscalationCurvePoint",
    "ThresholdSearchResult",
    "ConfidenceGate",
]
