from pathlib import Path
import pandas as pd, joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import numpy as np

BASE = Path(__file__).resolve().parents[1]

# URL
url_test = pd.read_csv(BASE / "data/URL/url_test.csv")
url_model = joblib.load(BASE / "models/url/xgboost_url_model.joblib")
X_test = url_test.drop(columns=["label"])
y_test = url_test["label"]
pred = url_model.predict(X_test)

# SMS
sms_test = pd.read_csv(BASE / "data/SMS/sms_test.csv")
model_dir = BASE / "models/bert_sms_model"
tokenizer = AutoTokenizer.from_pretrained(model_dir)
model = AutoModelForSequenceClassification.from_pretrained(model_dir)
model.eval()

preds = []
for text in sms_test["text"].tolist():
    inp = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=128)
    with torch.no_grad():
        out = model(**inp)
        prob = torch.softmax(out.logits, dim=1)[0,1].item()
    preds.append(1 if prob >= 0.5 else 0)

metrics = pd.DataFrame([
    {
        "model":"SMS BERT",
        "accuracy": accuracy_score(sms_test["label"], preds),
        "precision": precision_score(sms_test["label"], preds),
        "recall": recall_score(sms_test["label"], preds),
        "f1": f1_score(sms_test["label"], preds),
    },
    {
        "model":"URL XGBoost",
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1": f1_score(y_test, pred),
    }
])
metrics.to_csv(BASE / "data/model_metrics.csv", index=False)
print(metrics)
