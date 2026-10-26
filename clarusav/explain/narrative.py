"""Template-driven plain-English narrative explanation cards (no LLM)."""

from clarusav.explain.explainer import ExplanationResult


class NarrativeExplainer:
    """Generates plain-English narrative explanation cards from TreeSHAP attributions."""

    @staticmethod
    def generate_narrative_cards(explanation: ExplanationResult) -> list[str]:
        """Convert top SHAP feature contributions into human-readable narrative sentences."""
        cards: list[str] = []

        for feat in explanation.top_features:
            name = feat.feature_name
            val = feat.feature_value
            shap = feat.shap_value
            direction = "raised" if shap > 0 else "lowered"
            risk_label = "increased the malicious score" if shap > 0 else "reduced suspicion"

            if name == "max_section_entropy":
                if val >= 6.8:
                    impact_str = f"; this increased the malicious score by {abs(shap):.3f} {feat.units}." if shap > 0 else "."
                    cards.append(
                        f"High entropy ({val:.2f} bits) in sections indicates packed code or cryptographic encryption{impact_str}"
                    )
                elif val <= 4.0:
                    cards.append(
                        f"Low section entropy ({val:.2f} bits) indicates uncompressed, plain executable code; this {risk_label}."
                    )
                else:
                    cards.append(
                        f"Section entropy ({val:.2f} bits) is within typical executable range; this {direction} the score by {abs(shap):.3f} {feat.units}."
                    )

            elif name == "suspicious_import_count":
                if val > 0:
                    impact_str = f"; this increased the malicious score." if shap > 0 else "."
                    cards.append(
                        f"Detected {int(val)} imported function(s) matching high-risk security watchlist (process injection/memory manipulation){impact_str}"
                    )
                else:
                    cards.append(
                        f"Zero high-risk security watchlist APIs detected; this absence {risk_label}."
                    )

            elif name == "timestamp_anomaly":
                if val == 1.0:
                    cards.append(
                        f"Anomalous compile timestamp detected (zeroed, pre-1990, or post-dated); this indicator {risk_label}."
                    )
                else:
                    cards.append(
                        f"Compile timestamp falls within standard historical epoch range; this {risk_label}."
                    )

            elif name == "import_count":
                if val < 5:
                    cards.append(
                        f"Sparse import table ({int(val)} total functions) suggests dynamic API resolution or packing; this {risk_label}."
                    )
                else:
                    cards.append(
                        f"Import table contains {int(val)} standard library functions; this {direction} the score."
                    )

            elif name == "section_count":
                cards.append(
                    f"Binary contains {int(val)} section headers; this structural property {direction} the score."
                )

            elif name == "file_size":
                cards.append(
                    f"Binary file size of {int(val):,} bytes contributed {direction} the score."
                )

            else:
                cards.append(
                    f"Feature '{name}' (value: {val}) {direction} the verdict by {abs(shap):.3f} {feat.units}."
                )

        return cards
