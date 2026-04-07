import sys
import os

# FIX import path (IMPORTANT)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from utils.feature_extractor import extract_features

# LOAD TRAIN DATA
df = pd.read_csv("data/URL/url_train.csv")

rows = []

for _, row in df.iterrows():
    url = row["url"]
    label = row["label"]

    # EXTRACT FEATURES FROM URL
    features = extract_features(url)

    # ADD LABEL
    features["label"] = label

    rows.append(features)

# CREATE DATAFRAME
feature_df = pd.DataFrame(rows)

# SAVE NEW DATASET
feature_df.to_csv("data/URL/url_features_train.csv", index=False)

print("✅ Features created successfully!")
print(feature_df.head())