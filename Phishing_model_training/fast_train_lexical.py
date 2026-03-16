import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re
import os
import tldextract

print("Loading datasets for lexical training...")
# 1. Kaggle Dataset
kaggle_df = pd.read_csv("URL_Dataset/malicious_phish.csv")
kaggle_df["label"] = kaggle_df["type"].apply(lambda x: 1 if x in ["phishing", "malware", "defacement"] else 0)
kaggle_df = kaggle_df[["url", "label"]]

# 2. PhishTank Dataset
phishtank_df = pd.read_csv("URL_Dataset/verified_online.csv")
phishtank_df = phishtank_df[["url"]]
phishtank_df["label"] = 1

# 3. Top-1M Legitimate
top1m_df = pd.read_csv("URL_Dataset/top-1m.csv", header=None, on_bad_lines='skip')
top1m_df.columns = ["rank", "url"]
top1m_df = top1m_df[["url"]]
top1m_df["label"] = 0

# Combine datasets and take a balanced subset for fast, robust training
# Let's take 100k legitimate and 100k malicious
df_all = pd.concat([kaggle_df, phishtank_df, top1m_df], ignore_index=True).dropna(subset=['url'])
df_malicious = df_all[df_all["label"] == 1]
df_legit = df_all[df_all["label"] == 0]

# Subsample to avoid memory/time bottlenecks while retaining massive accuracy
# 100k of each is extremely robust for lexical models
df_mal_sub = df_malicious.sample(n=min(100000, len(df_malicious)), random_state=42)
df_leg_sub = df_legit.sample(n=min(100000, len(df_legit)), random_state=42)

df = pd.concat([df_mal_sub, df_leg_sub], ignore_index=True)
del df_all, df_malicious, df_legit, df_mal_sub, df_leg_sub

print(f"Dataset Balanced Shape: {df.shape}")
print("Extracting lexical features via vectorized pandas operations (SUPER FAST)...")

# --- Extract Features ---
# Ensure URLs have standard scheme 'http://' for extraction if missing, but we extract purely string-based features
urls = df['url'].astype(str)

# 1. Length features
df['url_length'] = urls.str.len()
df['path_length'] = urls.apply(lambda x: len(x.split('/', 3)[3]) if x.count('/') >= 3 else 0)

# 2. Character counts
df['dot_count'] = urls.str.count(r'\.')
df['hyphen_count'] = urls.str.count(r'-')
df['digit_count'] = urls.str.count(r'\d')
df['special_chars'] = urls.str.count(r'[@!#\$%\^&\*\(\)\+\=\[\]\{\}\|\\<>\?]')
df['at_symbol'] = urls.str.contains(r'@').astype(int)

# 3. Network/Protocol features
df['has_https'] = urls.str.contains(r'https://', case=False).astype(int)
df['has_ip'] = urls.str.contains(r'(?:\d{1,3}\.){3}\d{1,3}').astype(int)

# 4. TLD and subdomains
def extract_domain_info(url):
    ext = tldextract.extract(url)
    return ext.subdomain, ext.domain, ext.suffix

print("Running tldextract (this takes a few seconds)...")
tld_info = urls.apply(extract_domain_info)
df['subdomain_len'] = tld_info.apply(lambda x: len(x[0]))
df['domain_len'] = tld_info.apply(lambda x: len(x[1]))

# Suspicious TLD list (binary flag)
sus_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'buzz', 'info'}
df['sus_tld'] = tld_info.apply(lambda x: 1 if x[2].lower() in sus_tlds else 0)

# 5. Suspicious keywords in URL
sus_keywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'confirm']
pattern = '|'.join(sus_keywords)
df['has_sus_keyword'] = urls.str.contains(pattern, case=False).astype(int)

# 6. Entropy approximation (unique characters ratio)
df['char_diversity'] = urls.apply(lambda x: len(set(x)) / max(len(x), 1))

# --- Training phase ---
# Drop the raw URL column and prepare X, y
y = df['label']
X = df.drop(columns=['url', 'label'])

# Save feature names order
feature_names = list(X.columns)

print("Splitting...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Training Random Forest Classifier on pure lexical features...")
model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

print("\n--- Model Evaluation ---")
preds = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, preds):.4f}")
print(classification_report(y_test, preds))

print("\nFeature Importances:")
importances = model.feature_importances_
for name, imp in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True):
    print(f"{name:20s}: {imp:.4f}")

# --- Save Model ---
out_model = "../models/url_phishing_model.pkl"
joblib.dump(model, out_model)
print(f"\nModel strictly saved to {out_model}")

out_features = "../models/lexical_features.json"
import json
with open(out_features, "w") as f:
    json.dump(feature_names, f)
print(f"Features list saved to {out_features}")
