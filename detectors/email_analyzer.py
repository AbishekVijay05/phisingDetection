import email
import os
import re
import sys
from email import policy
from email.parser import BytesParser
from detectors.url_analyzer import analyze_url

# Urgency keywords
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'action required', 'act now', 'expire', 'suspended',
    'verify your', 'confirm your', 'update your', 'click here', 'click below',
    'limited time', 'within 24 hours', 'within 48 hours', 'account will be',
    'unauthorized', 'unusual activity', 'security alert', 'important notice',
    'final warning', 'last chance', 'penalty', 'legal action'
]

# Phishing content patterns
PHISHING_PATTERNS = [
    r'dear\s+(customer|user|member|account\s*holder)',
    r'we\s+(have\s+)?detected\s+(unusual|suspicious)',
    r'your\s+account\s+(has\s+been|will\s+be)\s+(suspend|lock|restrict|close|disable)',
    r'click\s+(here|below|the\s+link)',
    r'verify\s+your\s+(identity|account|information)',
    r'update\s+your\s+(payment|billing|account)',
    r'(you\s+have\s+won|congratulations|winner)',
    r'(password|credential|ssn|social\s+security)',
]

# Dangerous attachment extensions
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.js', '.jse',
    '.vbs', '.vbe', '.wsf', '.wsh', '.ps1', '.msi', '.dll', '.reg',
    '.hta', '.cpl', '.inf', '.lnk', '.jar'
}

# Known suspicious sender domains
SUSPICIOUS_SENDER_DOMAINS = {
    'mail.ru', 'yandex.ru', 'tempmail.com', 'guerrillamail.com',
    'throwaway.email', 'mailinator.com', 'sharklasers.com'
}


# ========================
# Hybrid ML model (emailphising02)
# ========================

_HYBRID_AVAILABLE = False
_NB_MODEL = None
_RO_MODEL = None
_ENSEMBLE_CLASS = None
_PREDICT_NB = None
_PREDICT_RO = None


def _init_hybrid_model():
    """
    Lazy-load the hybrid phishing model from the
    `emailphising02/phishing_detection_project` package.
    """
    global _HYBRID_AVAILABLE, _NB_MODEL, _RO_MODEL, _ENSEMBLE_CLASS, _PREDICT_NB, _PREDICT_RO

    if _HYBRID_AVAILABLE and _NB_MODEL is not None and _RO_MODEL is not None:
        return

    try:
        repo_root = os.path.dirname(os.path.dirname(__file__))
        emailproj_root = os.path.join(repo_root, "emailphising02")
        if emailproj_root not in sys.path:
            sys.path.append(emailproj_root)

        from phishing_detection_project.ensemble.hybrid_model import HybridEnsemble  # type: ignore
        from phishing_detection_project.model.naive_bayes_model import (  # type: ignore
            load_naive_bayes,
            predict_proba_phishing,
        )
        from phishing_detection_project.model.roberta_model import (  # type: ignore
            load_roberta,
            predict_proba_phishing_roberta,
        )

        artifacts_root = os.path.join(
            emailproj_root, "phishing_detection_project", "artifacts"
        )
        nb_dir = os.path.join(artifacts_root, "nb")
        roberta_dir = os.path.join(artifacts_root, "roberta")

        _NB_MODEL = load_naive_bayes(nb_dir)
        _RO_MODEL = load_roberta(roberta_dir)
        _ENSEMBLE_CLASS = HybridEnsemble
        _PREDICT_NB = predict_proba_phishing
        _PREDICT_RO = predict_proba_phishing_roberta
        _HYBRID_AVAILABLE = True
    except Exception:
        # If anything fails, we silently fall back to heuristic scoring.
        _HYBRID_AVAILABLE = False


def _hybrid_ml_score(text):
    """
    Use the hybrid model to produce:
    - score: 0–100
    - probability: 0–1
    - prediction: LEGITIMATE | PHISHING

    Falls back to zeros if unavailable or text is empty.
    """
    _init_hybrid_model()

    if not _HYBRID_AVAILABLE or not text or not text.strip():
        return {"score": 0.0, "probability": 0.0, "prediction": "LEGITIMATE", "available": False}

    try:
        ensemble = _ENSEMBLE_CLASS(mode="weighted", roberta_weight=0.7, nb_weight=0.3)
        nb_p = float(_PREDICT_NB(_NB_MODEL, [text])[0])
        ro_p = float(_PREDICT_RO(_RO_MODEL, [text])[0])
        final_p = float(ensemble.combine([ro_p], [nb_p])[0])
        p = float(max(0.0, min(1.0, final_p)))
        # Website label threshold: 0.61 (61%)
        pred = "PHISHING" if p >= 0.61 else "LEGITIMATE"
        return {"score": p * 100.0, "probability": p, "prediction": pred, "available": True}
    except Exception:
        return {"score": 0.0, "probability": 0.0, "prediction": "LEGITIMATE", "available": False}


def parse_eml_file(file_content):
    """Parse a .eml file and extract headers, body, links, and attachments."""
    try:
        if isinstance(file_content, str):
            file_content = file_content.encode('utf-8')
        msg = BytesParser(policy=policy.default).parsebytes(file_content)
    except Exception as e:
        return {'error': f'Failed to parse email: {str(e)}'}

    result = {
        'from': msg.get('From', ''),
        'to': msg.get('To', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'reply_to': msg.get('Reply-To', ''),
        'return_path': msg.get('Return-Path', ''),
        'received': msg.get_all('Received', []),
        'body_text': '',
        'body_html': '',
        'links': [],
        'attachments': [],
        'spf_status': 'unknown',
        'dkim_status': 'unknown',
    }

    # Extract SPF/DKIM from headers
    auth_results = msg.get('Authentication-Results', '')
    if auth_results:
        if 'spf=pass' in auth_results.lower():
            result['spf_status'] = 'pass'
        elif 'spf=fail' in auth_results.lower() or 'spf=softfail' in auth_results.lower():
            result['spf_status'] = 'fail'

        if 'dkim=pass' in auth_results.lower():
            result['dkim_status'] = 'pass'
        elif 'dkim=fail' in auth_results.lower():
            result['dkim_status'] = 'fail'

    # Extract body
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get('Content-Disposition', ''))

            if 'attachment' in disposition:
                filename = part.get_filename() or 'unknown'
                result['attachments'].append(filename)
            elif content_type == 'text/plain':
                try:
                    result['body_text'] = part.get_content()
                except Exception:
                    result['body_text'] = str(part.get_payload(decode=True) or b'', 'utf-8', errors='replace')
            elif content_type == 'text/html':
                try:
                    result['body_html'] = part.get_content()
                except Exception:
                    result['body_html'] = str(part.get_payload(decode=True) or b'', 'utf-8', errors='replace')
    else:
        content_type = msg.get_content_type()
        try:
            body = msg.get_content()
        except Exception:
            body = str(msg.get_payload(decode=True) or b'', 'utf-8', errors='replace')
        if content_type == 'text/html':
            result['body_html'] = body
        else:
            result['body_text'] = body

    # Extract links from HTML body
    all_text = result['body_text'] + ' ' + result['body_html']
    url_pattern = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')
    result['links'] = list(set(url_pattern.findall(all_text)))

    return result


def analyze_email_content(parsed_email):
    """Analyze parsed email content for phishing indicators."""
    checks = []
    score = 0

    sender = parsed_email.get('from', '')
    reply_to = parsed_email.get('reply_to', '')
    subject = parsed_email.get('subject', '')
    body = parsed_email.get('body_text', '') or parsed_email.get('body_html', '')
    links = parsed_email.get('links', [])
    attachments = parsed_email.get('attachments', [])

    # --- HEADER ANALYSIS ---

    # SPF check
    spf = parsed_email.get('spf_status', 'unknown')
    if spf == 'fail':
        checks.append({'name': 'SPF_FAILURE', 'status': 'fail', 'detail': 'Unauthorized sender IP'})
        score += 20
    elif spf == 'pass':
        checks.append({'name': 'SPF_PASS', 'status': 'pass', 'detail': 'Authorized sender IP'})
    else:
        checks.append({'name': 'SPF_UNKNOWN', 'status': 'warn', 'detail': 'SPF record not verifiable'})
        score += 5

    # DKIM check
    dkim = parsed_email.get('dkim_status', 'unknown')
    if dkim == 'fail':
        checks.append({'name': 'DKIM_FAILURE', 'status': 'fail', 'detail': 'Email signature invalid'})
        score += 15
    elif dkim == 'pass':
        checks.append({'name': 'DKIM_PASS', 'status': 'pass', 'detail': 'Verified domain signature'})
    else:
        checks.append({'name': 'DKIM_UNKNOWN', 'status': 'warn', 'detail': 'DKIM not verifiable'})
        score += 3

    # Sender vs Reply-To mismatch
    if reply_to and sender:
        sender_domain = _extract_domain(sender)
        reply_domain = _extract_domain(reply_to)
        if sender_domain and reply_domain and sender_domain != reply_domain:
            checks.append({'name': 'REPLY_TO_MISMATCH', 'status': 'fail', 'detail': f'Sender: {sender_domain}, Reply-To: {reply_domain}'})
            score += 15
        else:
            checks.append({'name': 'REPLY_TO_CHECK', 'status': 'pass', 'detail': 'Sender and Reply-To domains match'})

    # Suspicious sender domain
    sender_domain = _extract_domain(sender)
    if sender_domain and sender_domain.lower() in SUSPICIOUS_SENDER_DOMAINS:
        checks.append({'name': 'SUSPICIOUS_SENDER', 'status': 'fail', 'detail': f'Known suspicious domain: {sender_domain}'})
        score += 15

    # --- CONTENT ANALYSIS ---

    # Urgency keywords
    body_lower = (body + ' ' + subject).lower()
    urgency_found = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    urgency_score = min(len(urgency_found) * 5, 20)
    if urgency_found:
        checks.append({'name': 'URGENCY_KEYWORDS', 'status': 'fail', 'detail': f'Found: {", ".join(urgency_found[:5])}'})
        score += urgency_score
    else:
        checks.append({'name': 'URGENCY_CHECK', 'status': 'pass', 'detail': 'No urgency manipulation detected'})

    # Phishing patterns
    patterns_found = []
    for pattern in PHISHING_PATTERNS:
        if re.search(pattern, body_lower):
            patterns_found.append(pattern.split(r'\\')[0][:40])
    if patterns_found:
        checks.append({'name': 'PHISHING_PATTERNS', 'status': 'fail', 'detail': f'{len(patterns_found)} suspicious patterns detected'})
        score += min(len(patterns_found) * 5, 20)

    # --- LINK ANALYSIS ---
    link_results = []
    link_score = 0
    for link in links[:10]:  # analyze up to 10 links
        url_result = analyze_url(link)
        if 'error' not in url_result:
            link_results.append({
                'url': link,
                'rule_score': url_result['rule_score'],
            })
            link_score = max(link_score, url_result['rule_score'])

    if link_results:
        risky_links = [l for l in link_results if l['rule_score'] > 40]
        if risky_links:
            checks.append({'name': 'RISKY_LINKS', 'status': 'fail', 'detail': f'{len(risky_links)} suspicious links found'})
            score += min(link_score // 2, 20)
        else:
            checks.append({'name': 'LINK_ANALYSIS', 'status': 'pass', 'detail': f'{len(link_results)} links analyzed, none suspicious'})

    # --- ATTACHMENT ANALYSIS ---
    dangerous_attachments = [a for a in attachments if any(a.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)]
    if dangerous_attachments:
        checks.append({'name': 'DANGEROUS_ATTACHMENTS', 'status': 'fail', 'detail': f'Dangerous files: {", ".join(dangerous_attachments)}'})
        score += 25
    elif attachments:
        checks.append({'name': 'ATTACHMENTS', 'status': 'warn', 'detail': f'{len(attachments)} attachment(s) found'})
        score += 3

    score = min(score, 100)

    # Combine header/body content into a single text string for the ML model.
    ml_text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    hybrid = _hybrid_ml_score(ml_text)
    if not bool(hybrid.get("available", False)):
        # Fallback: use the existing heuristic ML score so the UI still shows
        # a meaningful confidence even when the hybrid artifacts aren't present.
        heur_score = float(_email_ml_heuristic(body_lower, urgency_found, patterns_found, link_score))
        heur_prob = max(0.0, min(1.0, heur_score / 100.0))
        hybrid = {
            "score": heur_score,
            "probability": heur_prob,
            "prediction": "PHISHING" if heur_prob >= 0.61 else "LEGITIMATE",
            "available": False,
        }

    return {
        'checks': checks,
        'rule_score': score,
        'ml_score': float(hybrid.get("score", 0.0)),
        'hybrid_probability': float(hybrid.get("probability", 0.0)),
        'hybrid_prediction': hybrid.get("prediction", "LEGITIMATE"),
        'hybrid_available': bool(hybrid.get("available", False)),
        'links_analyzed': link_results,
        'urgency_keywords': urgency_found,
        'sender_domain': sender_domain,
        'subject': subject,
    }


def analyze_email(file_content):
    """Complete email analysis pipeline."""
    parsed = parse_eml_file(file_content)
    if 'error' in parsed:
        return parsed

    analysis = analyze_email_content(parsed)
    analysis['parsed_headers'] = {
        'from': parsed.get('from', ''),
        'to': parsed.get('to', ''),
        'subject': parsed.get('subject', ''),
        'date': parsed.get('date', ''),
        'spf_status': parsed.get('spf_status', 'unknown'),
        'dkim_status': parsed.get('dkim_status', 'unknown'),
    }
    analysis['attachments'] = parsed.get('attachments', [])
    analysis['links'] = parsed.get('links', [])
    
    # Add body preview for Gemini/UI
    body = parsed.get('body_text', '') or parsed.get('body_html', '')
    analysis['body_preview'] = body[:500] if body else 'No body content'

    return analysis


def analyze_email_form(sender, subject, body, links_text=''):
    """Analyze email from structured form input (fallback)."""
    # Build a simplified parsed email dict
    parsed = {
        'from': sender,
        'to': '',
        'subject': subject,
        'body_text': body,
        'body_html': '',
        'reply_to': '',
        'links': re.findall(r'https?://[^\s]+', body + ' ' + links_text),
        'attachments': [],
        'spf_status': 'unknown',
        'dkim_status': 'unknown',
    }

    analysis = analyze_email_content(parsed)
    analysis['parsed_headers'] = {
        'from': sender,
        'subject': subject,
        'spf_status': 'unknown',
        'dkim_status': 'unknown',
    }
    analysis['attachments'] = []
    analysis['links'] = parsed['links']
    analysis['body_preview'] = body[:500] if body else 'No body content'

    return analysis


def _extract_domain(email_str):
    """Extract domain from email address string."""
    match = re.search(r'@([\w.-]+)', email_str)
    return match.group(1) if match else None


def _email_ml_heuristic(body_lower, urgency_found, patterns_found, link_score):
    """Deprecated heuristic kept for compatibility; no longer used."""
    score = 0
    score += min(len(urgency_found) * 7, 28)
    score += min(len(patterns_found) * 10, 30)
    score += min(link_score // 3, 20)
    if len(body_lower) < 100:
        score += 5
    return min(score, 100)
