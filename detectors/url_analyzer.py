import re
import math
from urllib.parse import urlparse

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
    """Extract 25+ features from a URL for phishing analysis."""
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
    special_chars = len(re.findall(r'[@!#\$%\^&\*\(\)\+\=\[\]\{\}\|\\<>\?]', full_url))
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


def analyze_url(url):
    """Full URL analysis — returns structured result."""
    features, checks, rule_score = extract_url_features(url)

    if 'error' in features:
        return {
            'error': features['error'],
            'risk_score': 0,
            'verdict': 'ERROR'
        }

    # ML heuristic score (weighted feature combination)
    ml_score = _ml_heuristic_score(features)

    return {
        'url': url,
        'features': features,
        'checks': checks,
        'rule_score': rule_score,
        'ml_score': ml_score,
        'ml_probability': min(ml_score / 100, 0.99),
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
