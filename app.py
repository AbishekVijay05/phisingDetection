from flask import Flask, render_template, request, jsonify
from config import Config
from models import db, Scan
from detectors.url_analyzer import analyze_url
from detectors.email_analyzer import analyze_email, analyze_email_form
from detectors.sms_analyzer import analyze_sms
from detectors.gemini_analyzer import analyze_url_with_gemini, analyze_email_with_gemini, analyze_sms_with_gemini
from detectors.scoring import build_result
import json
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload folder exists
os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)

db.init_app(app)

with app.app_context():
    db.create_all()


# ========================
# PAGE ROUTES
# ========================

@app.route('/')
def dashboard():
    return render_template('index.html', active='dashboard')

@app.route('/url')
def url_scanner():
    return render_template('url_scanner.html', active='url')

@app.route('/email')
def email_scanner():
    return render_template('email_scanner.html', active='email')

@app.route('/sms')
def sms_scanner():
    return render_template('sms_scanner.html', active='sms')

@app.route('/history')
def history():
    return render_template('history.html', active='history')


# ========================
# API ROUTES
# ========================

@app.route('/analyze/url', methods=['POST'])
def api_analyze_url():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # Layer 1 + 2: Rule-based + ML heuristic
    url_result = analyze_url(url)
    if 'error' in url_result:
        return jsonify(url_result), 400

    # Layer 3: Gemini AI
    gemini_result = analyze_url_with_gemini(url)

    # Combine scores
    try:
        parsed_domain = urlparse(url if '://' in url else 'http://' + url).hostname or url[:50]
    except Exception:
        parsed_domain = url[:50]

    result = build_result(
        scan_type='url',
        summary=parsed_domain,
        rule_score=url_result['rule_score'],
        ml_score=url_result['ml_score'],
        gemini_result=gemini_result,
        checks=url_result['checks'],
        extra={
            'url': url,
            'ml_probability': url_result.get('ml_probability', 0),
        }
    )

    # Save to database
    _save_scan(result)

    return jsonify(result)


@app.route('/analyze/email', methods=['POST'])
def api_analyze_email():
    # Check if file upload or form data
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        file_content = file.read()
        email_result = analyze_email(file_content)
    else:
        # Structured form input
        data = request.get_json() or request.form
        sender = data.get('sender', '').strip()
        subject = data.get('subject', '').strip()
        body = data.get('body', '').strip()
        links = data.get('links', '').strip()

        if not (sender or subject or body):
            return jsonify({'error': 'At least one field is required'}), 400

        email_result = analyze_email_form(sender, subject, body, links)

    if 'error' in email_result:
        return jsonify(email_result), 400

    # Layer 3: Gemini AI
    gemini_result = analyze_email_with_gemini(
        subject=email_result.get('parsed_headers', {}).get('subject', ''),
        body_preview=email_result.get('subject', ''),
        sender=email_result.get('parsed_headers', {}).get('from', ''),
        links=email_result.get('links', [])
    )

    summary = email_result.get('sender_domain', 'Unknown sender')

    result = build_result(
        scan_type='email',
        summary=summary or 'Email scan',
        rule_score=email_result['rule_score'],
        ml_score=email_result['ml_score'],
        gemini_result=gemini_result,
        checks=email_result['checks'],
        extra={
            'parsed_headers': email_result.get('parsed_headers', {}),
            'links': email_result.get('links', []),
            'attachments': email_result.get('attachments', []),
            'urgency_keywords': email_result.get('urgency_keywords', []),
        }
    )

    _save_scan(result)

    return jsonify(result)


@app.route('/analyze/sms', methods=['POST'])
def api_analyze_sms():
    data = request.get_json()
    message = data.get('message', '').strip()
    sender = data.get('sender', '').strip()

    if not message:
        return jsonify({'error': 'SMS message is required'}), 400

    # Layer 1 + 2
    sms_result = analyze_sms(message, sender)

    # Layer 3: Gemini
    gemini_result = analyze_sms_with_gemini(message, sender)

    result = build_result(
        scan_type='sms',
        summary=f'SMS from {sender}' if sender else 'SMS scan',
        rule_score=sms_result['rule_score'],
        ml_score=sms_result['ml_score'],
        gemini_result=gemini_result,
        checks=sms_result['checks'],
        extra={
            'message_preview': sms_result.get('message_preview', ''),
            'sender': sender,
            'content_flags': sms_result.get('content_flags', {}),
            'links_analyzed': sms_result.get('links_analyzed', []),
        }
    )

    _save_scan(result)

    return jsonify(result)


@app.route('/api/stats')
def api_stats():
    total = Scan.query.count()
    phishing = Scan.query.filter_by(verdict='PHISHING').count()
    suspicious = Scan.query.filter_by(verdict='SUSPICIOUS').count()
    safe = Scan.query.filter_by(verdict='SAFE').count()

    return jsonify({
        'total_scans': total,
        'phishing_caught': phishing,
        'suspicious_count': suspicious,
        'safe_count': safe,
    })


@app.route('/api/history')
def api_history():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    scans = Scan.query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'scans': [s.to_dict() for s in scans.items],
        'total': scans.total,
        'pages': scans.pages,
        'current_page': scans.page,
    })


def _save_scan(result):
    """Save scan result to database."""
    try:
        scan = Scan(
            scan_type=result.get('scan_type', 'unknown'),
            scan_summary=result.get('scan_summary', '')[:255],
            risk_score=result.get('risk_score', 0),
            verdict=result.get('verdict', 'SAFE'),
            details_json=json.dumps({
                'layer_scores': result.get('layer_scores', {}),
                'checks': result.get('checks', []),
                'gemini_analysis': result.get('gemini_analysis', ''),
            })
        )
        db.session.add(scan)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f'Error saving scan: {e}')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
