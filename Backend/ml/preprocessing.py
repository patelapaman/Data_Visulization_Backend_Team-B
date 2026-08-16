import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler


def prepare_ml_data(df):
    """
    Prepare security event data for machine learning.

    Steps:
    1. Copy the dataframe
    2. Remove unnecessary columns
    3. Convert categorical columns to numerical values
    4. Handle missing values
    5. Scale numerical features

    Parameters
    ----------
    df : pandas.DataFrame
        Engineered security event data.

    Returns
    -------
    processed_df : pandas.DataFrame
        ML-ready dataframe.

    scaler : StandardScaler
        Fitted scaler.
    """

    if df is None or df.empty:
        raise ValueError("Input dataframe is empty.")

    data = df.copy()

    # --------------------------------------------------
    # Remove duplicate records
    # --------------------------------------------------
    data.drop_duplicates(inplace=True)

    # --------------------------------------------------
    # Remove completely empty columns
    # --------------------------------------------------
    data.dropna(axis=1, how="all", inplace=True)

    # --------------------------------------------------
    # Convert boolean columns to integers
    # --------------------------------------------------
    boolean_columns = data.select_dtypes(
        include=["bool"]
    ).columns

    for column in boolean_columns:
        data[column] = data[column].astype(int)

    # --------------------------------------------------
    # Convert datetime columns
    # --------------------------------------------------
    datetime_columns = []

    for column in data.columns:

        if (
            "date" in column.lower()
            or "time" in column.lower()
            or "timestamp" in column.lower()
        ):

            try:
                converted = pd.to_datetime(
                    data[column],
                    errors="coerce"
                )

                if converted.notna().any():

                    # Extract useful time features
                    data[f"{column}_hour"] = converted.dt.hour
                    data[f"{column}_day"] = converted.dt.day
                    data[f"{column}_month"] = converted.dt.month
                    data[f"{column}_weekday"] = converted.dt.weekday

                    datetime_columns.append(column)

            except Exception:
                pass

    # Remove original datetime columns
    data.drop(
        columns=datetime_columns,
        errors="ignore",
        inplace=True
    )

    # --------------------------------------------------
    # Convert categorical columns
    # --------------------------------------------------
    categorical_columns = data.select_dtypes(
        include=["object", "category"]
    ).columns

    for column in categorical_columns:

        # Convert categories to numerical codes
        data[column] = (
            data[column]
            .astype(str)
            .fillna("Unknown")
        )

        data[column] = pd.factorize(
            data[column]
        )[0]

    # --------------------------------------------------
    # Replace infinity values
    # --------------------------------------------------
    data.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    # --------------------------------------------------
    # Fill numerical missing values
    # --------------------------------------------------
    numerical_columns = data.select_dtypes(
        include=["number"]
    ).columns

    for column in numerical_columns:

        median = data[column].median()

        if pd.isna(median):
            median = 0

        data[column] = data[column].fillna(median)

    # --------------------------------------------------
    # Remove constant columns
    # --------------------------------------------------
    for column in list(data.columns):

        if data[column].nunique() <= 1:
            data.drop(columns=[column], inplace=True)

    if data.empty:
        raise ValueError(
            "No usable numerical features found."
        )

    # --------------------------------------------------
    # Scale numerical features
    # --------------------------------------------------
    scaler = StandardScaler()

    numerical_columns = data.select_dtypes(
        include=["number"]
    ).columns

    if len(numerical_columns) > 0:

        data[numerical_columns] = scaler.fit_transform(
            data[numerical_columns]
        )

    print(
        f"ML preprocessing completed. "
        f"Rows: {len(data)}, "
        f"Features: {len(data.columns)}"
    )

    return data, scaler