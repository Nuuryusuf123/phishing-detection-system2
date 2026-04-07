import pandas as pd
from pathlib import Path
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

BASE = Path(__file__).resolve().parents[1]
train_df = pd.read_csv(BASE / "data/SMS/sms_train.csv")
val_df = pd.read_csv(BASE / "data/SMS/sms_val.csv")
test_df = pd.read_csv(BASE / "data/SMS/sms_test.csv")

MODEL_NAME = "distilbert-base-uncased"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize(batch):
    return tokenizer(batch["text"], truncation=True, padding="max_length", max_length=128)

train_ds = Dataset.from_pandas(train_df[["text","label"]]).map(tokenize, batched=True)
val_ds = Dataset.from_pandas(val_df[["text","label"]]).map(tokenize, batched=True)
test_ds = Dataset.from_pandas(test_df[["text","label"]]).map(tokenize, batched=True)

for ds in [train_ds, val_ds, test_ds]:
    ds.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])

model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary")
    acc = accuracy_score(labels, preds)
    return {"accuracy": acc, "precision": precision, "recall": recall, "f1": f1}

args = TrainingArguments(
    output_dir=str(BASE / "models/bert_sms_model"),
    evaluation_strategy="epoch",
    save_strategy="epoch",
    logging_steps=50,
    learning_rate=2e-5,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    num_train_epochs=2,
    weight_decay=0.01,
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    report_to="none"
)

trainer = Trainer(
    model=model,
    args=args,
    train_dataset=train_ds,
    eval_dataset=val_ds,
    tokenizer=tokenizer,
    compute_metrics=compute_metrics
)

trainer.train()
metrics = trainer.evaluate(test_ds)
print("BERT SMS metrics:", metrics)

trainer.save_model(BASE / "models/bert_sms_model")
tokenizer.save_pretrained(BASE / "models/bert_sms_model")
