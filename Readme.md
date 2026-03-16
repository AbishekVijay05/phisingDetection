# PhishGuard: AI-Powered Phishing Detection

PhishGuard is a comprehensive, multi-layered security platform designed to detect and analyze phishing attempts across URLs, emails, and SMS messages. By combining traditional rule-based heuristics with advanced Machine Learning and state-of-the-art Generative AI (Google Gemini), PhishGuard provides a robust defense against modern social engineering attacks.

## 🚀 Key Features

- **URL Scanner:** Analyzes links for malicious patterns, domain reputation, and lexical features.
- **Email Scanner:** Deep analysis of email headers, body content, and embedded links to identify phishing signatures and urgency.
- **SMS Scanner:** Scans text messages for suspicious links and common SMS phishing (smishing) content patterns.
- **Unified Dashboard:** Real-time statistics and a searchable history of all past scans.
- **Multi-Layered Scoring:** A weighted risk assessment (0-100) providing clear verdicts: **SAFE**, **SUSPICIOUS**, or **PHISHING**.

## 🛡️ Three-Layer Security Architecture

PhishGuard employs a unique triple-layer approach for maximum accuracy:

1.  **Rule-Based Heuristics (30% weight):** Fast, deterministic checks for known phishing patterns and signatures.
2.  **Machine Learning Prediction (30% weight):** Scikit-learn models trained on extensive phishing datasets to detect complex feature correlations.
3.  **Gemini AI Analysis (40% weight):** Advanced semantic analysis using Google's Gemini models to understand context, intent, and sophisticated social engineering tactics.

## 🌟 Advantages

- **High Accuracy:** The combination of three independent analysis layers significantly reduces false positives and negatives.
- **Semantic Intelligence:** Unlike traditional scanners, the Gemini AI layer can detect subtle psychological manipulation and social engineering that simple ML models might miss.
- **Real-Time Defense:** Instant feedback and analysis of potential threats.
- **Comprehensive Coverage:** A single tool to handle the three most common phishing vectors (Email, SMS, URL).
- **User-Centric Design:** Clear, actionable risk scores and detailed breakdown of why a particular scan was flagged.
- **Extensible:** Modular architecture allows for easy integration of new detection layers and threat vectors.

## 🛠️ Tech Stack

- **Backend:** Python (Flask)
- **Database:** SQLAlchemy (SQLite)
- **Machine Learning:** Scikit-learn
- **Generative AI:** Google Gemini (Generative AI SDK)
- **Frontend:** HTML5, CSS3, JavaScript

---
*Developed for advanced phishing protection and security awareness.*
