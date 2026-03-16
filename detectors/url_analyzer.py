import re
import math
import os
import json
import logging
import joblib
import tldextract
import numpy as np
import pandas as pd
from urllib.parse import urlparse

# ========================
# LOGGING SETUP
# ========================
logger = logging.getLogger('phishguard.url_analyzer')
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(name)s: %(message)s'
)

# ========================
# LOAD ML MODEL + FEATURE NAMES
# ========================
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'pro_phishing_model.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'pro_features.json')

# Load the canonical feature names saved during training
try:
    with open(FEATURES_PATH, 'r') as f:
        EXPECTED_FEATURES = json.load(f)
    logger.info(f"Loaded {len(EXPECTED_FEATURES)} canonical feature names from pro_features.json: {EXPECTED_FEATURES}")
except Exception as e:
    logger.error(f"Could not load feature names from {FEATURES_PATH}: {e}")
    EXPECTED_FEATURES = None

# Load the trained Pro ML model (HistGradientBoostingClassifier)
try:
    url_model = joblib.load(MODEL_PATH)
    logger.info(f"Loaded ML model from {MODEL_PATH} — type: {type(url_model).__name__}")
    if hasattr(url_model, 'n_features_in_'):
        logger.info(f"Model expects {url_model.n_features_in_} features")
        if EXPECTED_FEATURES and len(EXPECTED_FEATURES) != url_model.n_features_in_:
            logger.error(f"MISMATCH: pro_features.json has {len(EXPECTED_FEATURES)} features but model expects {url_model.n_features_in_}")
except Exception as e:
    logger.error(f"Could not load URL model: {e}")
    url_model = None

# ========================
# CONSTANTS
# ========================

# Well-known legitimate domains — used to cap false-positive risk
WELL_KNOWN_DOMAINS = {
    'google.com', 'www.google.com', 'youtube.com', 'www.youtube.com',
    'facebook.com', 'www.facebook.com', 'instagram.com', 'www.instagram.com',
    'twitter.com', 'www.twitter.com', 'x.com',
    'amazon.com', 'www.amazon.com', 'amazon.in', 'www.amazon.in',
    'microsoft.com', 'www.microsoft.com', 'linkedin.com', 'www.linkedin.com',
    'apple.com', 'www.apple.com', 'netflix.com', 'www.netflix.com',
    'github.com', 'www.github.com', 'stackoverflow.com',
    'wikipedia.org', 'en.wikipedia.org',
    'reddit.com', 'www.reddit.com',
    'whatsapp.com', 'web.whatsapp.com',
    'paypal.com', 'www.paypal.com',
    'mail.google.com', 'accounts.google.com', 'drive.google.com',
}

# Common suspicious TLDs
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.buzz', '.info', '.click', '.link', '.win', '.bid', '.stream', '.racing', '.icu', '.monster'}

# Known URL shorteners
URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at'}

# Common brand targets for typosquatting
BRAND_TARGETS = {
    'google': ['gogle', 'googl', 'gooogle', 'g00gle', 'googie', 'goog1e'],
    'facebook': ['facbook', 'facebok', 'faceb00k', 'faceboook', 'faccebook'],
    'amazon': ['amaz0n', 'amazom', 'amazone', 'arnazon', 'amazn'],
    'apple': ['appie', 'app1e', 'aple', 'applle'],
    'microsoft': ['micros0ft', 'microsft', 'mircosoft', 'microsoftt', 'micr0soft'],
    'netflix': ['netfIix', 'netfl1x', 'nettflix', 'netfiix'],
    'paypal': ['paypa1', 'paypai', 'paypaI', 'paypall', 'paypl'],
    'instagram': ['instagam', 'instgram', 'instagran', 'lnstagram'],
    'twitter': ['twiter', 'twtter', 'tvvitter', 'twltter'],
    'linkedin': ['linkedln', 'linkdin', 'l1nkedin', 'linkedn'],
    'whatsapp': ['whatsap', 'watsapp', 'whatspp', 'whatssapp'],
    'banking': ['bankofamerica', 'wellsfargo', 'chase', 'citi'],
}

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'confirm',
    'banking', 'password', 'credential', 'authenticate', 'suspend', 'locked',
    'unusual', 'activity', 'expire', 'urgent', 'alert', 'wallet', 'prize',
    'winner', 'free', 'gift', 'reward', 'claim', 'offer'
]


def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0
    prob = {}
    for c in text:
        prob[c] = prob.get(c, 0) + 1
    length = len(text)
    entropy = 0
    for count in prob.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def extract_url_features(url):
    """Extract 25+ features from a URL for phishing analysis (rule-based layer)."""
    features = {}
    checks = []

    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
    except Exception:
        return {'error': 'Invalid URL'}, [], 80

    hostname = parsed.hostname or ''
    path = parsed.path or ''
    full_url = url

    # --- STRING-BASED FEATURES ---

    # 1. URL Length
    url_length = len(full_url)
    features['url_length'] = url_length
    if url_length > 75:
        checks.append({'name': 'Excessive URL Length', 'status': 'fail', 'detail': f'{url_length} characters (suspicious > 75)'})
    else:
        checks.append({'name': 'URL Length', 'status': 'pass', 'detail': f'{url_length} characters (normal)'})

    # 2. Dot count
    dot_count = full_url.count('.')
    features['dot_count'] = dot_count
    if dot_count > 4:
        checks.append({'name': 'Excessive Dots', 'status': 'fail', 'detail': f'{dot_count} dots found'})

    # 3. Special characters
    special_chars = len(re.findall(r'[@!#\$%\^\&\*\(\)\+\=\[\]\{\}\|\\\<\>\?]', full_url))
    features['special_char_count'] = special_chars
    if special_chars > 2:
        checks.append({'name': 'Special Characters', 'status': 'fail', 'detail': f'{special_chars} suspicious characters'})

    # 4. Has @ symbol (credential harvesting trick)
    has_at = '@' in full_url
    features['has_at_symbol'] = has_at
    if has_at:
        checks.append({'name': '@ Symbol in URL', 'status': 'fail', 'detail': 'URL contains @ symbol (redirect trick)'})

    # 5. IP-based hostname
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    has_ip = bool(ip_pattern.match(hostname))
    features['ip_hostname'] = has_ip
    if has_ip:
        checks.append({'name': 'IP-based Hostname', 'status': 'fail', 'detail': 'Uses IP address instead of domain name'})
    else:
        checks.append({'name': 'IP-based Hostname', 'status': 'pass', 'detail': 'Uses domain name'})

    # 6. HTTPS check
    uses_https = parsed.scheme == 'https'
    features['uses_https'] = uses_https
    if uses_https:
        checks.append({'name': 'HTTPS Protocol', 'status': 'pass', 'detail': 'Secure connection'})
    else:
        checks.append({'name': 'HTTPS Protocol', 'status': 'fail', 'detail': 'No HTTPS - insecure connection'})

    # 7. Subdomain depth
    subdomain_parts = hostname.split('.')
    subdomain_depth = len(subdomain_parts) - 2 if len(subdomain_parts) > 2 else 0
    features['subdomain_depth'] = subdomain_depth
    if subdomain_depth > 2:
        checks.append({'name': 'Deep Subdomains', 'status': 'fail', 'detail': f'{subdomain_depth} subdomain levels'})

    # 8. Path length
    path_length = len(path)
    features['path_length'] = path_length
    if path_length > 50:
        checks.append({'name': 'Long Path', 'status': 'fail', 'detail': f'{path_length} characters in path'})

    # 9. Suspicious TLD
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
    is_suspicious_tld = tld.lower() in SUSPICIOUS_TLDS
    features['suspicious_tld'] = is_suspicious_tld
    if is_suspicious_tld:
        checks.append({'name': 'Suspicious TLD', 'status': 'fail', 'detail': f'TLD "{tld}" is commonly used in phishing'})
    else:
        checks.append({'name': 'TLD Check', 'status': 'pass', 'detail': f'TLD "{tld}" is standard'})

    # 10. URL shortener
    is_shortener = hostname.lower() in URL_SHORTENERS
    features['url_shortener'] = is_shortener
    if is_shortener:
        checks.append({'name': 'URL Shortener', 'status': 'warn', 'detail': 'Shortened URL hides true destination'})

    # 11. Hostname entropy
    entropy = calculate_entropy(hostname)
    features['hostname_entropy'] = round(entropy, 2)
    if entropy > 3.5:
        checks.append({'name': 'High Entropy Hostname', 'status': 'fail', 'detail': f'Entropy: {entropy:.2f} (random-looking domain)'})

    # 12. Typosquatting detection
    typosquat_detected = False
    typosquat_brand = ''
    hostname_lower = hostname.lower()
    for brand, variants in BRAND_TARGETS.items():
        if brand in hostname_lower:
            continue
        for variant in variants:
            if variant in hostname_lower:
                typosquat_detected = True
                typosquat_brand = brand
                break
        if typosquat_detected:
            break
    features['typosquatting'] = typosquat_detected
    if typosquat_detected:
        checks.append({'name': 'Typosquatting Detected', 'status': 'fail', 'detail': f'Impersonating "{typosquat_brand}"'})

    # 13. Suspicious keywords in URL
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url.lower()]
    features['suspicious_keywords'] = keywords_found
    if len(keywords_found) >= 2:
        checks.append({'name': 'Suspicious Keywords', 'status': 'fail', 'detail': f'Found: {", ".join(keywords_found[:5])}'})

    # 14. Hyphen count in domain
    hyphen_count = hostname.count('-')
    features['hyphen_count'] = hyphen_count
    if hyphen_count > 2:
        checks.append({'name': 'Excessive Hyphens', 'status': 'fail', 'detail': f'{hyphen_count} hyphens in domain'})

    # 15. Has port number
    has_port = parsed.port is not None and parsed.port not in (80, 443)
    features['unusual_port'] = has_port
    if has_port:
        checks.append({'name': 'Unusual Port', 'status': 'fail', 'detail': f'Port {parsed.port} (non-standard)'})

    # 16. Double slashes in path
    double_slash = '//' in path
    features['double_slash_path'] = double_slash
    if double_slash:
        checks.append({'name': 'Double Slash in Path', 'status': 'warn', 'detail': 'Redirect trick detected'})

    # 17. Has query parameters with suspicious names
    query = parsed.query or ''
    suspicious_params = any(p in query.lower() for p in ['password', 'token', 'session', 'redirect', 'return', 'next', 'callback'])
    features['suspicious_params'] = suspicious_params
    if suspicious_params:
        checks.append({'name': 'Suspicious Parameters', 'status': 'fail', 'detail': 'Query contains sensitive parameter names'})

    # --- CALCULATE RULE-BASED SCORE ---
    score = 0
    weights = {
        'url_length': 8 if url_length > 75 else (4 if url_length > 54 else 0),
        'ip_hostname': 20 if has_ip else 0,
        'no_https': 10 if not uses_https else 0,
        'suspicious_tld': 15 if is_suspicious_tld else 0,
        'shortener': 8 if is_shortener else 0,
        'typosquatting': 25 if typosquat_detected else 0,
        'high_entropy': 10 if entropy > 3.5 else 0,
        'deep_subdomains': 10 if subdomain_depth > 2 else 0,
        'keywords': min(len(keywords_found) * 5, 15),
        'at_symbol': 12 if has_at else 0,
        'special_chars': min(special_chars * 3, 10),
        'hyphens': 5 if hyphen_count > 2 else 0,
        'unusual_port': 8 if has_port else 0,
        'suspicious_params': 8 if suspicious_params else 0,
    }
    score = min(sum(weights.values()), 100)

    return features, checks, score


def _extract_pro_features(url):
    """
    Extract the exact 20 lexical features expected by the Pro ML model.
    
    CRITICAL: Features are built as a named dict, then reordered to match the
    canonical feature order saved in pro_features.json during training.
    This prevents silent ordering bugs.
    """
    # Clean the URL to exactly match the training dataset preprocessing (remove http, https, www)
    u = str(url).lower().strip()
    if u.startswith('http://'): u = u[7:]
    if u.startswith('https://'): u = u[8:]
    if u.startswith('www.'): u = u[4:]
    
    # Build features as a named dictionary first
    feat = {}
    
    # --- 1. Lengths ---
    url_length = len(u)
    feat['url_length'] = url_length
    feat['path_length'] = len(u[u.find('/'):]) if '/' in u else 0
    
    # --- 2. Counts ---
    feat['dot_count'] = u.count('.')
    feat['hyphen_count'] = u.count('-')
    feat['underscore_count'] = u.count('_')
    feat['slash_count'] = u.count('/')
    feat['question_count'] = u.count('?')
    feat['equal_count'] = u.count('=')
    feat['at_count'] = u.count('@')
    
    digit_count = sum(c.isdigit() for c in u)
    feat['digit_count'] = digit_count
    
    letter_count = sum(c.isalpha() for c in u)
    feat['letter_count'] = letter_count
    
    # --- 3. Ratios ---
    safe_len = max(url_length, 1)
    feat['digit_ratio'] = digit_count / safe_len
    
    vowels = len(re.findall(r'[aeiou]', u))
    feat['vowel_count'] = vowels
    feat['vowel_ratio'] = vowels / safe_len
    
    # --- 4. Network features ---
    feat['has_ip'] = 1 if re.search(r'(?:\d{1,3}\.){3}\d{1,3}', u) else 0
    
    # --- 5. TLDs and subdomains ---
    ext = tldextract.extract(u)
    feat['subdomain_len'] = len(ext.subdomain)
    feat['domain_len'] = len(ext.domain)
    
    sus_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'buzz', 'info', 'live', 'icu', 'vip'}
    feat['sus_tld'] = 1 if ext.suffix.lower() in sus_tlds else 0
    
    # --- 6. Keyword features ---
    sus_keywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'confirm', 'free', 'bonus', 'claim', 'admin', 'service', 'support']
    pattern = '|'.join(sus_keywords)
    feat['sus_keyword_count'] = len(re.findall(pattern, u, re.IGNORECASE))
    
    # --- 7. Entropy approximation ---
    feat['char_diversity'] = len(set(u)) / safe_len
    
    # --- CRITICAL: Reorder features to match canonical training order ---
    if EXPECTED_FEATURES:
        # Validate all expected features are present
        missing = [f for f in EXPECTED_FEATURES if f not in feat]
        if missing:
            logger.error(f"Missing features during extraction: {missing}")
        
        # Build the feature vector in the exact order the model was trained with
        feature_vector = [feat.get(name, 0) for name in EXPECTED_FEATURES]
    else:
        # Fallback: use dict insertion order (matches current training order)
        logger.warning("No canonical feature order loaded — using dict insertion order")
        feature_vector = list(feat.values())
    
    return feature_vector, feat


def _is_well_known_domain(url):
    """Check if the URL belongs to a well-known legitimate domain."""
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        hostname = (parsed.hostname or '').lower()
        
        # Direct match
        if hostname in WELL_KNOWN_DOMAINS:
            return True
        
        # Also check via tldextract for subdomains of well-known domains
        ext = tldextract.extract(url)
        base_domain = f"{ext.domain}.{ext.suffix}".lower()
        if base_domain in WELL_KNOWN_DOMAINS:
            return True
        
        return False
    except Exception:
        return False


def analyze_url(url):
    """Full URL analysis — returns structured result with debug logging."""
    logger.info(f"{'='*60}")
    logger.info(f"URL RECEIVED: {url}")
    logger.info(f"{'='*60}")

    features, checks, rule_score = extract_url_features(url)

    if 'error' in features:
        logger.error(f"Feature extraction error: {features['error']}")
        return {
            'error': features['error'],
            'risk_score': 0,
            'verdict': 'ERROR'
        }

    logger.info(f"Rule-based score: {rule_score}")
    logger.info(f"Rule-based features extracted: {len(features)} features")

    ml_score = 0
    ml_probability = 0.0

    if url_model:
        try:
            pro_features, feature_dict = _extract_pro_features(url)
            
            logger.info(f"ML Feature vector ({len(pro_features)} features): {pro_features}")
            logger.info(f"ML Feature names → values:")
            if EXPECTED_FEATURES:
                for name, val in zip(EXPECTED_FEATURES, pro_features):
                    logger.debug(f"  {name}: {val}")

            # VALIDATE feature vector length matches model expectation
            if hasattr(url_model, 'n_features_in_'):
                expected_count = url_model.n_features_in_
                actual_count = len(pro_features)
                if actual_count != expected_count:
                    logger.error(f"FEATURE COUNT MISMATCH! Model expects {expected_count}, got {actual_count}")
                    raise ValueError(f"Feature count mismatch: expected {expected_count}, got {actual_count}")
                logger.info(f"Feature count OK: {actual_count} == {expected_count}")

            # Build a DataFrame with proper column names to avoid sklearn warnings
            if EXPECTED_FEATURES:
                input_df = pd.DataFrame([pro_features], columns=EXPECTED_FEATURES)
                proba = url_model.predict_proba(input_df)[0]
            else:
                proba = url_model.predict_proba([pro_features])[0]
            
            # Find the 'phishing' class index (1)
            classes = url_model.classes_
            phishing_idx = list(classes).index(1) if 1 in classes else 0
            
            ml_probability = float(proba[phishing_idx])
            
            logger.info(f"Model classes: {list(classes)}")
            logger.info(f"Raw probabilities: {list(proba)}")
            logger.info(f"Phishing probability: {ml_probability:.4f}")

            # Apply well-known domain confidence adjustment
            if _is_well_known_domain(url):
                original_prob = ml_probability
                ml_probability = min(ml_probability, 0.05)  # Cap at 5% for known-good domains
                logger.info(f"Well-known domain detected — ML probability adjusted: {original_prob:.4f} → {ml_probability:.4f}")

            ml_score = int(ml_probability * 100)
            
            logger.info(f"Final ML score: {ml_score}")

        except Exception as e:
            logger.error(f"Model prediction error: {e}", exc_info=True)
            ml_score = _ml_heuristic_score(features)
            ml_probability = min(ml_score / 100, 0.99)
            logger.info(f"Fallback to heuristic ML score: {ml_score}")
    else:
        # ML heuristic score (fallback for no trained model)
        logger.warning("No ML model loaded — using heuristic scoring")
        ml_score = _ml_heuristic_score(features)
        ml_probability = min(ml_score / 100, 0.99)

    logger.info(f"FINAL RESULT — Rule: {rule_score}, ML: {ml_score} (prob: {ml_probability:.4f})")
    logger.info(f"{'='*60}")

    return {
        'url': url,
        'features': features,
        'checks': checks,
        'rule_score': rule_score,
        'ml_score': ml_score,
        'ml_probability': ml_probability,
    }


def _ml_heuristic_score(features):
    """ML-like heuristic scoring based on feature weights (fallback for no trained model)."""
    score = 0

    if features.get('ip_hostname'):
        score += 25
    if not features.get('uses_https'):
        score += 12
    if features.get('suspicious_tld'):
        score += 18
    if features.get('typosquatting'):
        score += 30
    if features.get('hostname_entropy', 0) > 3.5:
        score += 12
    if features.get('url_length', 0) > 75:
        score += 10
    if features.get('subdomain_depth', 0) > 2:
        score += 10
    if len(features.get('suspicious_keywords', [])) >= 2:
        score += 12
    if features.get('url_shortener'):
        score += 8
    if features.get('has_at_symbol'):
        score += 15

    return min(score, 100)
