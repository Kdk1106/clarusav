"""Explainability modules: TreeSHAP, Narrative Cards, and Counterfactuals."""

from clarusav.explain.counterfactual import CounterfactualExplainer, CounterfactualHint
from clarusav.explain.explainer import ExplanationResult, FeatureContribution, TreeSHAPExplainer
from clarusav.explain.narrative import NarrativeExplainer

__all__ = [
    "TreeSHAPExplainer",
    "ExplanationResult",
    "FeatureContribution",
    "NarrativeExplainer",
    "CounterfactualExplainer",
    "CounterfactualHint",
]
