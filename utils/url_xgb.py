import joblib
import pandas as pd
from pathlib import Path

MODEL = Path("models/url/xgboost_url_model.joblib")
COLS = Path("models/url/url_feature_columns.joblib")

def xgb_available():
    return MODEL.exists() and COLS.exists()

def predict_url(features: dict):
    model = joblib.load(MODEL)
    cols = joblib.load(COLS)

    print("Expected columns:", cols)
    print("Incoming feature keys:", list(features.keys()))

    row = pd.DataFrame([features])

    missing = [c for c in cols if c not in row.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")

    row = row[cols]

    score = float(model.predict_proba(row)[0][1])
    label = "Threat Detected" if score >= 0.5 else "Safe"

    importances = getattr(model, "feature_importances_", None)
    explain = []

    if importances is not None:
        pairs = sorted(
            zip(cols, importances, row.iloc[0].tolist()),
            key=lambda x: x[1],
            reverse=True
        )[:8]

        for c, imp, val in pairs:
            explain.append({
                "feature": c,
                "importance": float(imp),
                "value": float(val)
            })

    return label, score, explain
