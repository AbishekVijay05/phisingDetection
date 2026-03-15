import os

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


def _get_model():
    """Initialize Gemini model if API key is available."""
    api_key = os.environ.get('GEMINI_API_KEY', '')
    if not api_key or not GENAI_AVAILABLE:
        return None
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')
        return model
    except Exception:
        return None


def analyze_url_with_gemini(url, features=None):
    """Use Gemini to analyze a URL for phishing indicators."""
    model = _get_model()
    if not model:
        return {'available': False, 'analysis': 'Gemini API not configured', 'score': 0}

    prompt = f"""You are a cybersecurity expert analyzing URLs for phishing threats.

Analyze this URL for phishing indicators: {url}

Consider:
1. Domain reputation and legitimacy
2. Typosquatting or brand impersonation
3. URL structure anomalies
4. Known phishing patterns
5. Social engineering tactics

Respond in this exact format:
SCORE: [0-100 risk score]
VERDICT: [SAFE, SUSPICIOUS, or PHISHING]
ANALYSIS: [2-3 sentence analysis explaining your reasoning]
"""

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()
        return _parse_gemini_response(text)
    except Exception as e:
        return {'available': True, 'analysis': f'Analysis unavailable: {str(e)}', 'score': 0}


def analyze_email_with_gemini(subject='', body_preview='', sender='', links=None):
    """Use Gemini to analyze email content for phishing."""
    model = _get_model()
    if not model:
        return {'available': False, 'analysis': 'Gemini API not configured', 'score': 0}

    links_str = ', '.join(links[:5]) if links else 'None'
    # Truncate body preview
    body_preview = body_preview[:500] if body_preview else 'No body content'

    prompt = f"""You are a cybersecurity expert analyzing emails for phishing threats.

Analyze this email:
- From: {sender}
- Subject: {subject}
- Body Preview: {body_preview}
- Links found: {links_str}

Evaluate for:
1. Social engineering tactics (urgency, fear, greed)
2. Spoofing indicators
3. Suspicious links or attachments
4. Grammar/formatting anomalies typical of phishing
5. Whether this matches known phishing campaigns

Respond in this exact format:
SCORE: [0-100 risk score]
VERDICT: [SAFE, SUSPICIOUS, or PHISHING]
ANALYSIS: [2-3 sentence analysis explaining your reasoning]
"""

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()
        return _parse_gemini_response(text)
    except Exception as e:
        return {'available': True, 'analysis': f'Analysis unavailable: {str(e)}', 'score': 0}


def analyze_sms_with_gemini(message, sender=''):
    """Use Gemini to analyze SMS for phishing/scam indicators."""
    model = _get_model()
    if not model:
        return {'available': False, 'analysis': 'Gemini API not configured', 'score': 0}

    prompt = f"""You are a cybersecurity expert analyzing SMS messages for phishing and scam threats.

Analyze this SMS:
- Sender: {sender or 'Unknown'}
- Message: {message}

Evaluate for:
1. Smishing (SMS phishing) patterns
2. Urgency or fear tactics
3. Prize/lottery scam indicators
4. Suspicious links
5. Impersonation of legitimate services
6. OTP/verification code theft attempts

Respond in this exact format:
SCORE: [0-100 risk score]
VERDICT: [SAFE, SUSPICIOUS, or PHISHING]
ANALYSIS: [2-3 sentence analysis explaining your reasoning]
"""

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()
        return _parse_gemini_response(text)
    except Exception as e:
        return {'available': True, 'analysis': f'Analysis unavailable: {str(e)}', 'score': 0}


def _parse_gemini_response(text):
    """Parse structured response from Gemini."""
    result = {'available': True, 'score': 0, 'verdict': 'UNKNOWN', 'analysis': text}

    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if line.upper().startswith('SCORE:'):
            try:
                score_str = line.split(':', 1)[1].strip()
                # Extract just the number
                import re
                nums = re.findall(r'\d+', score_str)
                if nums:
                    result['score'] = min(int(nums[0]), 100)
            except (ValueError, IndexError):
                pass
        elif line.upper().startswith('VERDICT:'):
            verdict = line.split(':', 1)[1].strip().upper()
            if verdict in ('SAFE', 'SUSPICIOUS', 'PHISHING'):
                result['verdict'] = verdict
        elif line.upper().startswith('ANALYSIS:'):
            result['analysis'] = line.split(':', 1)[1].strip()

    return result
