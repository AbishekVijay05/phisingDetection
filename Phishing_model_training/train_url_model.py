import pandas as pd
import numpy as np
from scipy.io import arff
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from feature_extractor import extract_features

# --------------------------------------------
# STEP 1 — Load UCI Phishing Dataset (.arff)
# --------------------------------------------

print("Loading UCI phishing dataset...")

data = arff.loadarff("URL_Dataset/Training Dataset.arff")
uci_df = pd.DataFrame(data[0])

# Convert byte strings to normal strings
uci_df = uci_df.map(lambda x: x.decode() if isinstance(x, bytes) else x)

# Convert label: -1 (phishing) → 1, 1 (legitimate) → 0
uci_df["Result"] = uci_df["Result"].astype(int)
uci_df["Result"] = uci_df["Result"].apply(lambda x: 1 if x == -1 else 0)

print("UCI Dataset Loaded")
print("Dataset Shape:", uci_df.shape)
print()


# --------------------------------------------
# STEP 2 — Load Kaggle Malicious URL Dataset
# --------------------------------------------

print("Loading Kaggle malicious URL dataset...")

kaggle_df = pd.read_csv("URL_Dataset/malicious_phish.csv")

# Keep required columns
kaggle_df = kaggle_df[["url", "type"]]

# Convert to binary labels
# phishing / malware / defacement → 1
# benign → 0
kaggle_df["label"] = kaggle_df["type"].apply(
    lambda x: 1 if x in ["phishing", "malware", "defacement"] else 0
)

kaggle_df = kaggle_df[["url", "label"]]

print("Kaggle Dataset Loaded")
print("Kaggle Dataset Shape:", kaggle_df.shape)
print()


# --------------------------------------------
# STEP 3 — Load PhishTank Dataset
# --------------------------------------------

print("Loading PhishTank dataset...")

phishtank_df = pd.read_csv("URL_Dataset/verified_online.csv")

# Keep only URL column
phishtank_df = phishtank_df[["url"]]

# Assign phishing label (1 = phishing)
phishtank_df["label"] = 1

print("PhishTank Dataset Loaded")
print("PhishTank Dataset Shape:", phishtank_df.shape)
print()


# --------------------------------------------
# STEP 4 — Load Top-1M Legitimate URLs Dataset
# --------------------------------------------

print("Loading Top-1M legitimate URLs dataset...")

top1m_df = pd.read_csv("URL_Dataset/top-1m.csv", header=None)

# Rename columns to match expected format
top1m_df.columns = ["rank", "url"]

# Keep only URL column
top1m_df = top1m_df[["url"]]

# Assign legitimate label (0 = legitimate)
top1m_df["label"] = 0

print("Top-1M Dataset Loaded")
print("Top-1M Dataset Shape:", top1m_df.shape)
print()


# --------------------------------------------
# STEP 5 — Extract Features from URL Datasets
# --------------------------------------------

print("Extracting features from Kaggle URLs...")

kaggle_features = []
kaggle_labels = []

for _, row in kaggle_df.iterrows():
    try:
        f = extract_features(row["url"])
        kaggle_features.append(f)
        kaggle_labels.append(row["label"])
    except:
        continue

print("Kaggle feature extraction completed")
print()

print("Extracting features from PhishTank URLs...")

phishtank_features = []
phishtank_labels = []

for _, row in phishtank_df.iterrows():
    try:
        f = extract_features(row["url"])
        phishtank_features.append(f)
        phishtank_labels.append(row["label"])
    except:
        continue

print("PhishTank feature extraction completed")
print()

print("Extracting features from Top-1M URLs...")

top1m_features = []
top1m_labels = []

for _, row in top1m_df.iterrows():
    try:
        f = extract_features(row["url"])
        top1m_features.append(f)
        top1m_labels.append(row["label"])
    except:
        continue

print("Top-1M feature extraction completed")
print()


# --------------------------------------------
# STEP 6 — Combine All Datasets
# --------------------------------------------

print("Combining all datasets...")

# Convert extracted features to DataFrames
kaggle_X = pd.DataFrame(kaggle_features)
kaggle_y = pd.Series(kaggle_labels)

phishtank_X = pd.DataFrame(phishtank_features)
phishtank_y = pd.Series(phishtank_labels)

top1m_X = pd.DataFrame(top1m_features)
top1m_y = pd.Series(top1m_labels)

# Prepare UCI data
X_uci = uci_df.drop("Result", axis=1)
y_uci = uci_df["Result"]

# Convert all column names to strings for consistency
X_uci.columns = X_uci.columns.astype(str)
kaggle_X.columns = kaggle_X.columns.astype(str)
phishtank_X.columns = phishtank_X.columns.astype(str)
top1m_X.columns = top1m_X.columns.astype(str)

# Combine all datasets
X = pd.concat([X_uci, kaggle_X, phishtank_X, top1m_X], ignore_index=True)
y = pd.concat([y_uci, kaggle_y, phishtank_y, top1m_y], ignore_index=True)

print("Final Dataset Shape:", X.shape)
print("Label Distribution:")
print(y.value_counts())
print()


# --------------------------------------------
# STEP 7 — Train/Test Split
# --------------------------------------------

print("Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))
print()

# --------------------------------------------
# STEP 8 — Train Random Forest Model
# --------------------------------------------

print("Training Random Forest model...")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=25,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Model training completed")
print()

# --------------------------------------------
# STEP 9 — Evaluate Model
# --------------------------------------------

print("Evaluating model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("Model Accuracy:", accuracy)
print()

print("Classification Report:")
print(classification_report(y_test, predictions))
print()

# --------------------------------------------
# STEP 10 — Save Model
# --------------------------------------------

joblib.dump(model, "url_phishing_model.pkl")

print("Model saved as url_phishing_model.pkl")