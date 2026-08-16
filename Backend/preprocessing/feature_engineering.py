import os
import pandas as pd
import numpy as np


OUTPUT_FOLDER = "outputs"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# =========================================================
# Helper Functions
# =========================================================

def safe_numeric(df, column, default=0):
    """
    Convert a column to numeric safely.
    If the column does not exist, create it with default value.
    """

    if column in df.columns:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        ).fillna(default)

    else:

        df[column] = default

    return df


def safe_boolean(df, column, default=False):
    """
    Convert a column to boolean safely.
    """

    if column not in df.columns:

        df[column] = default

        return df

    df[column] = (
        df[column]
        .astype(str)
        .str.lower()
        .isin([
            "true",
            "1",
            "yes",
            "y",
            "malware",
            "detected"
        ])
    )

    return df


# =========================================================
# Main Feature Engineering Function
# =========================================================

def engineer_features(df):
    """
    Create machine-learning features from enriched
    security event data.

    Parameters
    ----------
    df : pandas.DataFrame
        Enriched security event dataframe.

    Returns
    -------
    pandas.DataFrame
        Feature-engineered dataframe.
    """

    if df is None or df.empty:

        raise ValueError(
            "Input dataframe is empty."
        )

    data = df.copy()

    print("\nStarting Feature Engineering...\n")

    # =====================================================
    # 1. Standardize column names
    # =====================================================

    data.columns = (
        data.columns
        .str.strip()
        .str.lower()
        .str.replace(" ", "_", regex=False)
    )

    # =====================================================
    # 2. Numeric Security Features
    # =====================================================

    numeric_columns = [
        "cvss_score",
        "threat_score",
        "failed_login_attempts",
        "login_frequency",
        "connection_frequency",
        "unique_destination_count",
        "events_per_user",
        "unique_ip_count",
        "vulnerability_count"
    ]

    for column in numeric_columns:

        data = safe_numeric(
            data,
            column
        )

    # =====================================================
    # 3. Severity Score
    # =====================================================

    if "severity_score" not in data.columns:

        if "severity" in data.columns:

            severity_mapping = {
                "critical": 100,
                "high": 80,
                "medium": 60,
                "low": 30,
                "unknown": 0
            }

            data["severity_score"] = (
                data["severity"]
                .astype(str)
                .str.lower()
                .map(severity_mapping)
                .fillna(0)
            )

        else:

            data["severity_score"] = 0

    else:

        data = safe_numeric(
            data,
            "severity_score"
        )

    # =====================================================
    # 4. Malware Detection
    # =====================================================

    data = safe_boolean(
        data,
        "malware_detected"
    )

    # =====================================================
    # 5. Impossible Travel
    # =====================================================

    data = safe_boolean(
        data,
        "impossible_travel_flag"
    )

    # =====================================================
    # 6. Timestamp Processing
    # =====================================================

    timestamp_column = None

    possible_timestamp_columns = [
        "timestamp",
        "event_time",
        "event_timestamp",
        "datetime",
        "date_time",
        "created_at"
    ]

    for column in possible_timestamp_columns:

        if column in data.columns:

            timestamp_column = column

            break

    if timestamp_column:

        timestamp = pd.to_datetime(
            data[timestamp_column],
            errors="coerce"
        )

        # -------------------------------------------------
        # Login/event hour
        # -------------------------------------------------

        data["login_hour"] = (
            timestamp.dt.hour
            .fillna(0)
            .astype(int)
        )

        # -------------------------------------------------
        # Day of week
        # -------------------------------------------------

        data["day_of_week"] = (
            timestamp.dt.dayofweek
            .fillna(0)
            .astype(int)
        )

        # -------------------------------------------------
        # Month
        # -------------------------------------------------

        data["event_month"] = (
            timestamp.dt.month
            .fillna(0)
            .astype(int)
        )

        # -------------------------------------------------
        # After-hours activity
        # -------------------------------------------------

        data["after_hours_activity"] = (
            (data["login_hour"] < 6)
            |
            (data["login_hour"] >= 22)
        )

        # -------------------------------------------------
        # Weekend activity
        # -------------------------------------------------

        data["weekend_activity"] = (
            data["day_of_week"] >= 5
        )

    else:

        data["login_hour"] = 0

        data["day_of_week"] = 0

        data["event_month"] = 0

        data["after_hours_activity"] = False

        data["weekend_activity"] = False

    # =====================================================
    # 7. Failed Login Risk
    # =====================================================

    data["failed_login_risk"] = (
        data["failed_login_attempts"]
        .clip(upper=20)
        * 5
    )

    # =====================================================
    # 8. High CVSS Flag
    # =====================================================

    data["high_cvss_flag"] = (
        data["cvss_score"] >= 7
    )

    # =====================================================
    # 9. Critical CVSS Flag
    # =====================================================

    data["critical_cvss_flag"] = (
        data["cvss_score"] >= 9
    )

    # =====================================================
    # 10. High Threat Flag
    # =====================================================

    data["high_threat_flag"] = (
        data["threat_score"] >= 70
    )

    # =====================================================
    # 11. Critical Threat Flag
    # =====================================================

    data["critical_threat_flag"] = (
        data["threat_score"] >= 90
    )

    # =====================================================
    # 12. Event Frequency
    # =====================================================

    if "asset_id" in data.columns:

        asset_counts = (
            data["asset_id"]
            .value_counts()
        )

        data["event_frequency"] = (
            data["asset_id"]
            .map(asset_counts)
            .fillna(1)
        )

    elif "user_id" in data.columns:

        user_counts = (
            data["user_id"]
            .value_counts()
        )

        data["event_frequency"] = (
            data["user_id"]
            .map(user_counts)
            .fillna(1)
        )

    else:

        data["event_frequency"] = 1

    # =====================================================
    # 13. Events Per User
    # =====================================================

    if "user_id" in data.columns:

        user_counts = (
            data["user_id"]
            .value_counts()
        )

        data["events_per_user"] = (
            data["user_id"]
            .map(user_counts)
            .fillna(1)
        )

    else:

        data["events_per_user"] = 1

    # =====================================================
    # 14. Unique IP Count
    # =====================================================

    if "user_id" in data.columns and "source_ip" in data.columns:

        ip_counts = (
            data.groupby("user_id")[
                "source_ip"
            ]
            .transform("nunique")
        )

        data["unique_ip_count"] = (
            ip_counts.fillna(1)
        )

    elif "source_ip" in data.columns:

        data["unique_ip_count"] = (
            data["source_ip"]
            .nunique()
        )

    else:

        data["unique_ip_count"] = 1

    # =====================================================
    # 15. Unique Destination Count
    # =====================================================

    if "destination_ip" in data.columns:

        data["unique_destination_count"] = (
            data["destination_ip"]
            .nunique()
        )

    elif "destination" in data.columns:

        data["unique_destination_count"] = (
            data["destination"]
            .nunique()
        )

    else:

        data["unique_destination_count"] = 1

    # =====================================================
    # 16. Connection Frequency
    # =====================================================

    if "source_ip" in data.columns:

        source_counts = (
            data["source_ip"]
            .value_counts()
        )

        data["connection_frequency"] = (
            data["source_ip"]
            .map(source_counts)
            .fillna(1)
        )

    else:

        data["connection_frequency"] = 1

    # =====================================================
    # 17. Login Frequency
    # =====================================================

    if "user_id" in data.columns:

        login_counts = (
            data["user_id"]
            .value_counts()
        )

        data["login_frequency"] = (
            data["user_id"]
            .map(login_counts)
            .fillna(1)
        )

    else:

        data["login_frequency"] = 1

    # =====================================================
    # 18. Overall Behavioral Risk
    # =====================================================

    data["behavioral_risk_score"] = (

        data["failed_login_risk"] * 0.25

        +

        data["event_frequency"]
        .clip(upper=20)
        * 2

        +

        data["connection_frequency"]
        .clip(upper=20)
        * 1.5

        +

        data["after_hours_activity"]
        .astype(int)
        * 15

        +

        data["impossible_travel_flag"]
        .astype(int)
        * 20

    ).clip(upper=100)

    # =====================================================
    # 19. Final Threat Score
    # =====================================================

    if "threat_score" not in data.columns:

        data["threat_score"] = 0

    data["threat_score"] = (
        data["threat_score"]
        .clip(
            lower=0,
            upper=100
        )
    )

    # =====================================================
    # 20. Combined Risk Score
    # =====================================================

    data["combined_risk_score"] = (

        data["threat_score"] * 0.40

        +

        data["severity_score"] * 0.20

        +

        data["behavioral_risk_score"] * 0.20

        +

        data["failed_login_risk"] * 0.10

        +

        data["malware_detected"]
        .astype(int)
        * 10

    ).clip(
        upper=100
    )

    # =====================================================
    # 21. Replace Infinity / Missing Values
    # =====================================================

    data.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    numerical_columns = data.select_dtypes(
        include=["number"]
    ).columns

    for column in numerical_columns:

        data[column] = (
            data[column]
            .fillna(0)
        )

    # =====================================================
    # 22. Save Output
    # =====================================================

    output_path = os.path.join(
        OUTPUT_FOLDER,
        "engineered_features.csv"
    )

    data.to_csv(
        output_path,
        index=False
    )

    print(
        f"\nFeature Engineering Completed."
    )

    print(
        f"Total Records: {len(data)}"
    )

    print(
        f"Total Features: {len(data.columns)}"
    )

    print(
        f"Saved: {output_path}"
    )

    return data


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":

    try:

        from data_collection import load_data
        from data_cleaning import clean_data
        from threat_enrichment import enrich_threat_data

        datasets = load_data()

        cleaned = clean_data(
            datasets
        )

        enriched = enrich_threat_data(
            cleaned
        )

        engineered = engineer_features(
            enriched
        )

        print(
            "\nEngineered Feature Preview:"
        )

        print(
            engineered.head()
        )

    except Exception as error:

        print(
            f"Feature Engineering Error: {error}"
        )