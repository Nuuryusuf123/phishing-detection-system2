import pandas as pd, joblib
from pathlib import Path
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

BASE = Path(__file__).resolve().parents[1]
train = pd.read_csv(BASE / "data/URL/url_train.csv")
val = pd.read_csv(BASE / "data/URL/url_val.csv")
test = pd.read_csv(BASE / "data/URL/url_test.csv")

X_train, y_train = train.drop(columns=["label"]), train["label"]
X_val, y_val = val.drop(columns=["label"]), val["label"]
X_test, y_test = test.drop(columns=["label"]), test["label"]

model = XGBClassifier(
    n_estimators=180,
    max_depth=5,
    learning_rate=0.08,
    subsample=0.9,
    colsample_bytree=0.9,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    n_jobs=4
)
model.fit(X_train, y_train)

pred = model.predict(X_test)
metrics = {
    "accuracy": accuracy_score(y_test, pred),
    "precision": precision_score(y_test, pred),
    "recall": recall_score(y_test, pred),
    "f1": f1_score(y_test, pred),
}
print("URL model metrics:", metrics)

out_dir = BASE / "models/url"
out_dir.mkdir(parents=True, exist_ok=True)
joblib.dump(model, out_dir / "xgboost_url_model.joblib")
joblib.dump(list(X_train.columns), out_dir / "url_feature_columns.joblib")
