import pandas as pd

from ml.scoring import (
    score_event,
    score_dataframe
)

from ml.rules import (
    check_security_rules,
    apply_rules
)


class ScoringService:
    """
    Service responsible for threat scoring
    and security-rule evaluation.
    """

    # --------------------------------------------------
    # Score one event
    # --------------------------------------------------

    def score_event(self, event):

        if isinstance(
            event,
            pd.Series
        ):

            event = event.to_dict()

        if not isinstance(
            event,
            dict
        ):

            raise TypeError(
                "Event must be a dictionary "
                "or pandas Series."
            )

        score = score_event(
            event
        )

        rules = check_security_rules(
            event
        )

        return {
            **score,
            **rules
        }

    # --------------------------------------------------
    # Score multiple events
    # --------------------------------------------------

    def score_dataframe(self, df):

        if df is None or df.empty:

            raise ValueError(
                "Dataframe is empty."
            )

        scored = score_dataframe(
            df
        )

        scored = apply_rules(
            scored
        )

        return scored

    # --------------------------------------------------
    # Get risk level
    # --------------------------------------------------

    def get_risk_level(
        self,
        confidence_score
    ):

        try:

            score = float(
                confidence_score
            )

        except (
            ValueError,
            TypeError
        ):

            score = 0

        if score >= 90:
            return "Critical"

        elif score >= 70:
            return "High"

        elif score >= 40:
            return "Medium"

        return "Low"


# ------------------------------------------------------
# Convenience function
# ------------------------------------------------------

def calculate_event_score(event):

    service = ScoringService()

    return service.score_event(
        event
    )