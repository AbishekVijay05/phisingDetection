# PhishGuard: Technical Methods and Algorithms

PhishGuard employs a multi-layered detection strategy to identify phishing attempts across URL, Email, and SMS vectors. This document outlines the specific methods, feature extraction techniques, and algorithms used in the system.

## 1. Multi-Layer Scoring Engine

The core of PhishGuard is a weighted scoring engine that combines three independent analysis layers:

| Layer | Weight | Methodology |
| :--- | :--- | :--- |
| **Layer 1: Rule-Based** | 30% | Heuristic checks, regex patterns, and deterministic signatures. |
| **Layer 2: Machine Learning** | 30% | Statistical models (HistGradientBoosting) trained on lexical features. |
| **Layer 3: Gemini AI** | 40% | Semantic analysis using LLMs to detect social engineering intent. |

**Final Risk Score Calculation:**
- If Gemini is available: `(Rule * 0.3) + (ML * 0.3) + (Gemini * 0.4)`
- If Gemini is unavailable: `(Rule * 0.5) + (ML * 0.5)`

---

## 2. URL Analysis Methodology

The URL analyzer processes raw strings to extract 25+ features for both heuristic and ML layers.

### Lexical Feature Extraction
- **Entropy Analysis:** Calculates Shannon Entropy of hostnames to detect random-looking generated domains (DGA).
- **Structural Features:** Dot count, hyphen count, underscore count, slash count, and URL length.
- **Credential Harvesting Detection:** Checks for '@' symbols and IP-based hostnames.
- **Security Protocols:** Verification of HTTPS vs. HTTP.
- **TLD Analysis:** Checks against a database of high-risk TLDs (e.g., `.tk`, `.ml`, `.xyz`).

### Typosquatting Algorithm
A specialized algorithm detects brand impersonation by comparing the hostname against a known list of high-value targets (e.g., `g00gle.com` vs `google.com`) using variant matching and string distance heuristics.

### ML Algorithm (URL)
- **Model:** `HistGradientBoostingClassifier` (Scikit-learn).
- **Input:** A 20-dimensional feature vector including digit ratios, vowel ratios, subdomain depth, and keyword counts.
- **Adjustment:** Results for well-known domains (e.g., `google.com`, `microsoft.com`) are automatically capped to prevent false positives.

---

## 3. Email Analysis Methodology

The email scanner focuses on both technical headers and semantic content.

### Header Parsing & Authentication
- **SPF/DKIM Validation:** Parses `Authentication-Results` headers to verify sender legitimacy.
- **Domain Mismatch:** Compares `From` vs. `Reply-To` and `Return-Path` domains to detect spoofing.
- **Suspicious Sender DB:** Matches sender domains against known "burner" or high-risk email providers.

### Content & Attachment Analysis
- **Regex Pattern Matching:** Detects common phishing greetings ("Dear Customer") and threat patterns ("Your account will be suspended").
- **Urgency Detection:** Weighted keyword matching for high-pressure language.
- **Attachment Filtering:** Flags high-risk file extensions (e.g., `.exe`, `.vbs`, `.js`, `.scr`).
- **Integrated URL Scanning:** Automatically extracts and scans all embedded links using the URL Analysis engine.

---

## 4. SMS Analysis Methodology (Smishing)

SMS analysis is optimized for short, text-heavy content where technical headers are minimal.

### Semantic Categorization
The engine categorizes SMS content into five risk vectors:
1.  **Urgency:** "Act now," "Within 24 hours."
2.  **Prize/Lottery:** "Winner," "Claim your reward."
3.  **Threat:** "Blocked," "Unusual activity," "Legal action."
4.  **Financial:** References to banks, taxes (IRS), or refunds.
5.  **OTP Scams:** Detection of patterns requesting "One Time Passwords" or "Verification Codes."

### Sender Analysis
- **Short Code Detection:** Identifies 5-6 digit short codes (common for both legitimate services and mass-phishing).
- **Format Verification:** Validates international phone number formats vs. suspicious alphanumeric senders.

---

## 5. Gemini AI Layer (Semantic Logic)

The Generative AI layer uses specialized prompts to perform **Intent Analysis**:
- **Role:** Acts as a veteran cybersecurity analyst.
- **Input:** Raw text, extracted links, and sender information.
- **Output:** A semantic risk score and a natural language explanation of the "why" behind the threat.
- **Capability:** Detects subtle manipulation tactics that bypass keyword-based filters, such as complex social engineering or novel "vishing" (voice-phishing) scripts.

---

## 6. Verdict Mapping

The final weighted score is mapped to a verdict:
- **SAFE (0 - 30):** Minimal risk detected.
- **SUSPICIOUS (31 - 65):** Multiple flags; user should proceed with extreme caution.
- **PHISHING (66 - 100):** High-confidence malicious intent detected.
