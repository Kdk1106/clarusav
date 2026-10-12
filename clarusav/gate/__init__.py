"""Confidence gating and decision engine for ClarusAV."""

from clarusav.gate.engine import (
    BandPosition,
    ConfidenceGate,
    EscalationCurvePoint,
    GateDecision,
    ThresholdSearchResult,
    Verdict,
)
from clarusav.gate.uncertainty import DualSignalDecision, DualSignalGate

__all__ = [
    "BandPosition",
    "Verdict",
    "GateDecision",
    "EscalationCurvePoint",
    "ThresholdSearchResult",
    "ConfidenceGate",
    "DualSignalDecision",
    "DualSignalGate",
]
