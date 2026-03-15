# Final Plan — Let's Lock It Down

## Email Input — My Recommendation

Since pasting email content is bad UX, here are two practical options I suggest we implement:

| Method | How it works | Effort |
|--------|-------------|--------|
| **Upload .eml file** | User goes to Gmail → "Show Original" → "Download Original" → uploads to our app. Python's built-in `email` library parses it automatically | ~2 hours |
| **Structured Form (fallback)** | Form with fields: Sender, Subject, Body, Links — for quick checks | ~30 mins |

**Both are doable. The .eml upload is the primary, form is the backup.**

Does this approach work for you?

---

## Complete Architecture

```
┌──────────────────────────────────────────────────────┐
│           Flask Web App (Frontend + Backend)          │
│                                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────────┐  │
│  │  URL Page  │  │ Email Page │  │   SMS Page     │  │
│  │ paste URL  │  │ upload .eml│  │  paste message │  │
│  └─────┬──────┘  └─────┬──────┘  └───────┬────────┘  │
│        │               │                 │            │
│        ▼               ▼                 ▼            │
│  ┌─────────────────────────────────────────────────┐  │
│  │              Flask API Routes                   │  │
│  │   /analyze/url  /analyze/email  /analyze/sms    │  │
│  │                /history  /stats                  │  │
│  └────────┬────────────┬──────────────┬────────────┘  │
│           │            │              │                │
│           ▼            ▼              ▼                │
│  ┌─────────────────────────────────────────────────┐  │
│  │           Detection Engine                      │  │
│  │                                                 │  │
│  │  Layer 1: Rule-Based Heuristics (instant)       │  │
│  │  Layer 2: Lightweight ML - sklearn (instant)    │  │
│  │  Layer 3: Gemini API (1-2 sec)                  │  │
│  │                                                 │  │
│  │  → Combined Risk Score (0-100)                  │  │
│  │  → Verdict: SAFE / SUSPICIOUS / PHISHING        │  │
│  │  → Detailed breakdown of why                    │  │
│  └─────────────────────┬───────────────────────────┘  │
│                        │                              │
│                        ▼                              │
│  ┌─────────────────────────────────────────────────┐  │
│  │         SQLite Database                         │  │
│  │  Stores: scan history, stats (no personal data) │  │
│  └─────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Flask (Python) |
| Frontend | Jinja2 Templates + HTML/CSS/JS + Bootstrap 5 |
| Database | SQLite (via Flask-SQLAlchemy) |
| ML Models | scikit-learn (Random Forest, Logistic Regression) |
| LLM | Google Gemini API (free tier) |
| URL features | `tldextract`, `urllib`, `requests`, `whois` |
| Email parsing | Python built-in `email` library |
| Visualization | Chart.js (for dashboard stats) |

---

## Database Schema (Privacy-Friendly)

```
scans
├── id              (auto-increment)
├── scan_type       (url / email / sms)
├── scan_summary    (domain only for URL, sender domain for email, "SMS #id" for SMS)
├── risk_score      (0-100)
├── verdict         (SAFE / SUSPICIOUS / PHISHING)
├── details_json    (JSON: which features triggered, layer-wise scores)
├── created_at      (timestamp)

stats (aggregated)
├── total_scans
├── phishing_caught
├── safe_count
├── suspicious_count
```

**What we DON'T store:** full email body, full SMS text, email addresses, phone numbers, user identity.

---

## Detection Features Per Channel

### URL Analyzer (25+ features)
```
String-based:        URL length, dot count, special char count,
                     has IP address, subdomain depth, path length
Suspicion signals:   Typosquatting detection (gooogle.com),
                     suspicious TLD (.xyz, .tk, .top),
                     URL shortener detected, HTTPS missing
External checks:     Domain age (whois), Google Safe Browsing API (free)
ML Model:            sklearn Random Forest trained on URL dataset
Gemini:              "Analyze this URL for phishing indicators"
```

### Email Analyzer
```
Header analysis:     SPF/DKIM check, sender vs reply-to mismatch,
                     suspicious sender domain
Content analysis:    Urgency keywords score, grammar errors,
                     too-good-to-be-true offers
Link extraction:     Extract all URLs → run each through URL analyzer
Attachment check:    Flag dangerous extensions (.exe, .js, .scr)
ML Model:            TF-IDF + Logistic Regression on email corpus
Gemini:              "Is this email phishing? Explain why."
```

### SMS Analyzer
```
Content signals:     Urgency score, prize/lottery keywords,
                     threat language, OTP scam patterns
Link extraction:     Extract URLs → run through URL analyzer
Sender analysis:     Short code vs long number patterns
ML Model:            TF-IDF + Logistic Regression on SMS spam dataset
Gemini:              "Analyze this SMS for phishing/scam indicators"
```

---

## Datasets to Download

| Dataset | For | Source |
|---------|-----|--------|
| PhishTank | URL phishing | phishtank.org (free, CSV download) |
| UCI Phishing Websites | URL features | Kaggle |
| Nazario Phishing Corpus | Email phishing | monkey.org/~jose/phishing |
| SpamAssassin Public Corpus | Email spam/ham | spamassassin.apache.org |
| SMS Spam Collection | SMS | UCI ML Repository / Kaggle |

---

## Team Division (6 People × 24 Hours)

```
┌─────────────────────────────────────────────────────┐
│ Person 1 & 2: FRONTEND                              │
│  → Dashboard UI, URL/Email/SMS input pages          │
│  → Results display (risk meter, breakdown)          │
│  → Scan history page, stats with Chart.js           │
│  → Make it look polished (this wins hackathons!)     │
├─────────────────────────────────────────────────────┤
│ Person 3: BACKEND + DATABASE                        │
│  → Flask app setup, API routes, SQLite models       │
│  → .eml file upload + parsing                       │
│  → Score aggregation logic (combine 3 layers)       │
│  → Scan history & stats endpoints                   │
├─────────────────────────────────────────────────────┤
│ Person 4: URL DETECTION ENGINE                      │
│  → Feature extraction from URLs                     │
│  → Rule-based scoring                               │
│  → Train sklearn model on phishing URL dataset      │
│  → Google Safe Browsing API integration             │
├─────────────────────────────────────────────────────┤
│ Person 5: EMAIL + SMS DETECTION ENGINE              │
│  → TF-IDF + ML models for email & SMS              │
│  → Rule-based keyword/pattern scoring              │
│  → Link extraction from email/SMS → feed to URL     │
├─────────────────────────────────────────────────────┤
│ Person 6: GEMINI INTEGRATION + FINAL SCORING        │
│  → Gemini API integration for all 3 channels       │
│  → Prompt engineering for best results              │
│  → Combined scoring algorithm                       │
│  → Testing with real phishing examples              │
└─────────────────────────────────────────────────────┘
```

---

## Timeline (24 Hours)

```
Hour 0-1:    Setup — Git repo, Flask skeleton, folder structure,
             everyone installs dependencies

Hour 1-4:    Parallel development begins
             Frontend: wireframe + basic pages
             Backend: routes + DB models
             ML team: download datasets, start training
             Gemini: test prompts, get API working

Hour 4-8:    Core features working
             Frontend: functional forms, results display
             Backend: all 3 /analyze endpoints working
             Detectors: rule-based + ML models ready
             Gemini: integrated into detection pipeline

Hour 8-12:   INTEGRATION — Connect everything
             Frontend ↔ Backend fully connected
             All 3 channels producing real scores
             Database storing scan history

Hour 12-16:  Polish + Edge Cases
             Better UI, animations, risk meter visual
             Handle errors gracefully
             History page with charts
             Test with real phishing examples

Hour 16-20:  Testing + Bug Fixes
             Test all flows end-to-end
             Fix breaking bugs
             Performance optimization

Hour 20-24:  Demo Preparation
             Prepare demo script
             Create sample phishing examples to show
             Final UI polish
             Prepare presentation slides
```

---

## Key Questions Before We Start Coding

1. **Does this overall plan look good to you?**
2. **Do you have a Gemini API key ready?** (Need to get one from ai.google.dev)
3. **The .eml upload + structured form approach for email — are you okay with both?**
4. **Any feature you want to ADD or REMOVE from this plan?**
5. **Do you want a simple login system** (anonymous sessions) or completely open (anyone visits, scans, and sees global history)?

Once you confirm, I'll start with the **project structure and code** — beginning with the Flask skeleton that everyone can build on simultaneously.