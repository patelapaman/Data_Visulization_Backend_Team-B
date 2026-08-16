import pandas as pd


# ------------------------------------------------------
# Important cybersecurity features
# ------------------------------------------------------

DEFAULT_FEATURES = [
    "failed_login_attempts",
    "login_frequency",
    "login_hour",
    "connection_frequency",
    "unique_destination_count",
    "events_per_user",
    "unique_ip_count",
    "after_hours_activity",
    "cvss_score",
    "vulnerability_count",
    "severity_score",
    "malware_detected",
    "event_frequency",
    "impossible_travel_flag",
    "threat_score"
]


def select_features(
    df,
    feature_list=None
):
    """
    Select relevant features for ML models.

    Parameters
    ----------
    df : pandas.DataFrame
        Engineered security event data.

    feature_list : list, optional
        List of desired features.

    Returns
    -------
    pandas.DataFrame
        Selected feature dataframe.
    """

    if df is None or df.empty:
        raise ValueError(
            "Input dataframe is empty."
        )

    data = df.copy()

    if feature_list is None:
        feature_list = DEFAULT_FEATURES

    # --------------------------------------------------
    # Find features that actually exist
    # --------------------------------------------------

    available_features = [
        feature
        for feature in feature_list
        if feature in data.columns
    ]

    # --------------------------------------------------
    # If predefined features don't exist,
    # automatically use numerical columns
    # --------------------------------------------------

    if not available_features:

        available_features = list(
            data.select_dtypes(
                include=["number"]
            ).columns
        )

    if not available_features:

        raise ValueError(
            "No suitable ML features were found."
        )

    selected_data = data[
        available_features
    ].copy()

    print("\nSelected ML Features:")

    for feature in available_features:
        print(f"  ✓ {feature}")

    print(
        f"\nTotal selected features: "
        f"{len(available_features)}"
    )

    return selected_data


def get_feature_names(df):
    """
    Return names of selected features.
    """

    if df is None or df.empty:
        return []

    return list(df.columns)