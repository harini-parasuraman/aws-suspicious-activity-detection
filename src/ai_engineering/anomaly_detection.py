"""Isolation Forest scoring for aggregated activity features."""
import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURE_COLUMNS = [
    "failed_login_count",
    "api_call_count",
    "distinct_event_count",
    "access_denied_count",
    "security_change_count",
]


def score_anomalies(
    features: pd.DataFrame,
    contamination: float = 0.1,
    random_state: int = 42,
) -> pd.DataFrame:
    """Fit a demonstration model and score rows. Use a separate baseline/test split for evaluation."""
    result = features.copy()
    if result.empty:
        result["anomaly_label"] = pd.Series(dtype="int64")
        result["anomaly_score"] = pd.Series(dtype="float64")
        result["is_anomaly"] = pd.Series(dtype="bool")
        return result

    missing = [col for col in FEATURE_COLUMNS if col not in result.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    X = result[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0)
    if len(X) < 2:
        result["anomaly_label"] = 1
        result["anomaly_score"] = 0.0
        result["is_anomaly"] = False
        return result

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X)
    result["anomaly_label"] = model.predict(X)
    result["anomaly_score"] = model.decision_function(X)
    result["is_anomaly"] = result["anomaly_label"].eq(-1)
    return result
