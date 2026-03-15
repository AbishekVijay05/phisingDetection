import re
from detectors.url_analyzer import analyze_url

# SMS phishing keywords by category
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'act now', 'expire', 'suspended', 'locked',
    'final notice', 'last chance', 'within 24', 'within 48', 'right away'
]

PRIZE_KEYWORDS = [
    'winner', 'won', 'prize', 'lottery', 'congratulations', 'selected',
    'reward', 'free gift', 'claim', 'lucky', 'jackpot', 'cash prize'
]

THREAT_KEYWORDS = [
    'suspended', 'blocked', 'unauthorized', 'unusual activity', 'compromised',
    'disabled', 'restricted', 'penalty', 'legal action', 'arrest', 'warrant'
]

OTP_SCAM_PATTERNS = [
    r'your\s+(otp|code|pin)\s+is',
    r'verification\s+code',
    r'do\s+not\s+share',
    r'one[\s-]?time\s+password',
]

FINANCIAL_KEYWORDS = [
    'bank', 'credit card', 'debit card', 'payment', 'transaction',
    'transfer', 'refund', 'irs', 'tax', 'loan', 'insurance'
]

ACTION_KEYWORDS = [
    'click', 'tap', 'visit', 'go to', 'open', 'call', 'dial', 'reply',
    'send', 'confirm', 'verify', 'update', 'download', 'install'
]


def analyze_sms(message, sender=''):
    """Complete SMS phishing analysis."""
    checks = []
    score = 0
    message_lower = message.lower()

    # --- CONTENT ANALYSIS ---

    # Urgency detection
    urgency_found = [kw for kw in URGENCY_KEYWORDS if kw in message_lower]
    if urgency_found:
        checks.append({
            'name': 'Urgency Language',
            'status': 'fail',
            'detail': f'Found: {", ".join(urgency_found[:3])}'
        })
        score += min(len(urgency_found) * 8, 20)
    else:
        checks.append({
            'name': 'Urgency Check',
            'status': 'pass',
            'detail': 'No urgency manipulation detected'
        })

    # Prize/lottery scam detection
    prize_found = [kw for kw in PRIZE_KEYWORDS if kw in message_lower]
    if prize_found:
        checks.append({
            'name': 'Prize/Lottery Scam',
            'status': 'fail',
            'detail': f'Found: {", ".join(prize_found[:3])}'
        })
        score += min(len(prize_found) * 10, 25)

    # Threat language
    threat_found = [kw for kw in THREAT_KEYWORDS if kw in message_lower]
    if threat_found:
        checks.append({
            'name': 'Threat Language',
            'status': 'fail',
            'detail': f'Found: {", ".join(threat_found[:3])}'
        })
        score += min(len(threat_found) * 8, 20)

    # OTP scam patterns
    otp_matches = [p for p in OTP_SCAM_PATTERNS if re.search(p, message_lower)]
    if otp_matches:
        checks.append({
            'name': 'OTP/Code Pattern',
            'status': 'warn',
            'detail': 'Contains OTP-related content'
        })
        score += 10

    # Financial keywords
    financial_found = [kw for kw in FINANCIAL_KEYWORDS if kw in message_lower]
    if financial_found:
        checks.append({
            'name': 'Financial Content',
            'status': 'warn',
            'detail': f'References: {", ".join(financial_found[:3])}'
        })
        score += min(len(financial_found) * 5, 15)

    # Action keywords
    action_found = [kw for kw in ACTION_KEYWORDS if kw in message_lower]
    if action_found and (urgency_found or threat_found or prize_found):
        checks.append({
            'name': 'Call to Action',
            'status': 'fail',
            'detail': f'Pressuring action: {", ".join(action_found[:3])}'
        })
        score += 10

    # --- LINK ANALYSIS ---
    url_pattern = re.compile(r'https?://[^\s]+|www\.[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+')
    links = url_pattern.findall(message)

    link_results = []
    link_max_score = 0
    for link in links[:5]:
        url_result = analyze_url(link)
        if 'error' not in url_result:
            link_results.append({
                'url': link,
                'rule_score': url_result['rule_score'],
            })
            link_max_score = max(link_max_score, url_result['rule_score'])

    if link_results:
        risky = [l for l in link_results if l['rule_score'] > 40]
        if risky:
            checks.append({
                'name': 'Suspicious Links',
                'status': 'fail',
                'detail': f'{len(risky)} risky link(s) detected'
            })
            score += min(link_max_score // 2, 25)
        else:
            checks.append({
                'name': 'Link Analysis',
                'status': 'pass',
                'detail': f'{len(link_results)} link(s) analyzed, appear safe'
            })
    elif any(word in message_lower for word in ['click', 'tap', 'visit', 'go to']):
        # Mentions clicking but no actual link (could be hidden)
        checks.append({
            'name': 'Missing Link',
            'status': 'warn',
            'detail': 'Mentions action but link may be hidden'
        })

    # --- SENDER ANALYSIS ---
    if sender:
        # Short codes are typically 5-6 digits
        if re.match(r'^\d{4,6}$', sender):
            checks.append({
                'name': 'Short Code Sender',
                'status': 'warn',
                'detail': f'Short code: {sender} (legitimate services use these, but so do scams)'
            })
        elif re.match(r'^\+?\d{10,15}$', sender):
            checks.append({
                'name': 'Standard Number',
                'status': 'pass',
                'detail': f'Standard phone number format'
            })
        elif sender:
            checks.append({
                'name': 'Sender Format',
                'status': 'warn',
                'detail': f'Non-standard sender: {sender}'
            })

    # --- ML HEURISTIC ---
    ml_score = _sms_ml_heuristic(
        urgency_found, prize_found, threat_found,
        financial_found, action_found, link_max_score, len(message)
    )

    score = min(score, 100)

    return {
        'message_preview': message[:100] + ('...' if len(message) > 100 else ''),
        'sender': sender,
        'checks': checks,
        'rule_score': score,
        'ml_score': ml_score,
        'links_analyzed': link_results,
        'content_flags': {
            'urgency': urgency_found,
            'prizes': prize_found,
            'threats': threat_found,
            'financial': financial_found,
            'actions': action_found,
        }
    }


def _sms_ml_heuristic(urgency, prizes, threats, financial, actions, link_score, msg_length):
    """ML-like heuristic scoring for SMS."""
    score = 0
    score += min(len(urgency) * 10, 25)
    score += min(len(prizes) * 12, 25)
    score += min(len(threats) * 10, 20)
    score += min(len(financial) * 5, 10)
    if actions and (urgency or threats or prizes):
        score += 10
    score += min(link_score // 3, 15)
    if msg_length < 30:
        score += 0  # too short to judge
    return min(score, 100)
