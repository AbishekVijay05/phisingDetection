import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re
import tldextract

print("Loading high-quality datasets...")
# 1. Kaggle Dataset (contains realistic benign URLs with paths, bypassing the Top-1M bias)
kaggle_df = pd.read_csv("URL_Dataset/malicious_phish.csv")
kaggle_df["label"] = kaggle_df["type"].apply(lambda x: 1 if x in ["phishing", "malware", "defacement"] else 0)
kaggle_df = kaggle_df[["url", "label"]]

# 2. PhishTank Dataset (high quality verified phishing)
phishtank_df = pd.read_csv("URL_Dataset/verified_online.csv")
phishtank_df = phishtank_df[["url"]]
phishtank_df["label"] = 1

df = pd.concat([kaggle_df, phishtank_df], ignore_index=True).dropna(subset=['url'])
print(f"Dataset Shape: {df.shape}")

print("Cleaning URLs to prevent feature leaks (removing scheme/www)...")
# CRITICAL: Strip http, https, and www so the model learns from the actual domain/path, not dataset artifacts
def clean_url_str(u):
    u = str(u).lower().strip()
    if u.startswith('http://'): u = u[7:]
    if u.startswith('https://'): u = u[8:]
    if u.startswith('www.'): u = u[4:]
    return u

df['clean_url'] = df['url'].apply(clean_url_str)
urls = df['clean_url']

print("Extracting unbiased lexical features...")

# Generate Features
X = pd.DataFrame()

# Lengths
X['url_length'] = urls.str.len()
X['path_length'] = urls.apply(lambda x: len(x[x.find('/'):]) if '/' in x else 0)

# Counts
X['dot_count'] = urls.str.count(r'\.')
X['hyphen_count'] = urls.str.count(r'-')
X['underscore_count'] = urls.str.count(r'_')
X['slash_count'] = urls.str.count(r'/')
X['question_count'] = urls.str.count(r'\?')
X['equal_count'] = urls.str.count(r'=')
X['at_count'] = urls.str.count(r'@')
X['digit_count'] = urls.str.count(r'\d')
X['letter_count'] = urls.str.count(r'[a-z]')

# Ratios
X['digit_ratio'] = X['digit_count'] / X['url_length'].replace(0, 1)
X['vowel_count'] = urls.str.count(r'[aeiou]')
X['vowel_ratio'] = X['vowel_count'] / X['url_length'].replace(0, 1)

# IP presence
X['has_ip'] = urls.str.contains(r'(?:\d{1,3}\.){3}\d{1,3}').astype(int)

# TLDs & Subdomains
def extract_domain_info(u):
    ext = tldextract.extract(u)
    return len(ext.subdomain), len(ext.domain), ext.suffix

print("Running NLP TLD Extractions...")
tld_info = urls.apply(extract_domain_info)
X['subdomain_len'] = tld_info.apply(lambda x: x[0])
X['domain_len'] = tld_info.apply(lambda x: x[1])

sus_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'buzz', 'info', 'live', 'icu', 'vip'}
X['sus_tld'] = tld_info.apply(lambda x: 1 if x[2].lower() in sus_tlds else 0)

# Keywords
sus_keywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'confirm', 'free', 'bonus', 'claim', 'admin', 'service', 'support']
pattern = '|'.join(sus_keywords)
X['sus_keyword_count'] = urls.str.count(pattern)

# Entropy (Fast approximation)
X['char_diversity'] = urls.apply(lambda x: len(set(x)) / max(len(x), 1))

y = df['label']
feature_names = list(X.columns)

print("Splitting...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42)

print("Training Advanced HistGradientBoosting Model (SOTA for Tabular)...")
model = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, max_depth=15, random_state=42)
model.fit(X_train, y_train)

print("\n--- Model Evaluation ---")
preds = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, preds):.4f}")
print(classification_report(y_test, preds))

# Save
out_model = "../models/pro_phishing_model.pkl"
joblib.dump(model, out_model)
print(f"\nModel securely saved to {out_model}")

import json
out_features = "../models/pro_features.json"
with open(out_features, "w") as f:
    json.dump(feature_names, f)
print(f"Features list saved to {out_features}")
