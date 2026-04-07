import sys
import os

# FIX import path (IMPORTANT)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# LOAD DATASET (FEATURES)
df = pd.read_csv("data/URL/url_features_train.csv")

# SPLIT FEATURES AND LABEL
X = df.drop("label", axis=1)
y = df["label"]

# TRAIN / TEST SPLIT
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# TRAIN MODEL
model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42
)

model.fit(X_train, y_train)

# PREDICT
y_pred = model.predict(X_test)

# EVALUATION
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# SAVE MODEL
joblib.dump(model, "models/url/xgboost_url_model.joblib")
joblib.dump(list(X.columns), "models/url/url_feature_columns.joblib")

print("\n✅ Model saved successfully for Automatic URL Detection (PRO)!")