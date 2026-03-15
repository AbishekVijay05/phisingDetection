def calculate_combined_score(rule_score, ml_score, gemini_result=None):
    """
    Combine scores from all 3 layers into a final 0-100 risk score.

    Weights:
    - Rule-based heuristics: 30%
    - ML prediction: 30%
    - Gemini AI analysis: 40%

    If Gemini is unavailable or failed, redistribute:
    - Rule-based: 50%
    - ML prediction: 50%
    """
    if gemini_result and gemini_result.get('success'):
        gemini_score = gemini_result.get('score', 0)
        combined = (rule_score * 0.30) + (ml_score * 0.30) + (gemini_score * 0.40)
    else:
        combined = (rule_score * 0.50) + (ml_score * 0.50)

    combined = min(max(combined, 0), 100)
    return round(combined, 1)


def get_verdict(risk_score):
    """Map risk score to verdict."""
    if risk_score >= 66:
        return 'PHISHING'
    elif risk_score >= 31:
        return 'SUSPICIOUS'
    else:
        return 'SAFE'


def build_result(scan_type, summary, rule_score, ml_score, gemini_result, checks, extra=None):
    """Build standardized analysis result."""
    combined_score = calculate_combined_score(rule_score, ml_score, gemini_result)
    verdict = get_verdict(combined_score)

    result = {
        'scan_type': scan_type,
        'scan_summary': summary,
        'risk_score': combined_score,
        'verdict': verdict,
        'layer_scores': {
            'rule_based': round(rule_score, 1),
            'ml_prediction': round(ml_score, 1),
            'gemini_ai': gemini_result.get('score', 0) if gemini_result and gemini_result.get('success') else 0,
        },
        'gemini_analysis': gemini_result.get('analysis', 'Not available') if gemini_result else 'Not configured',
        'gemini_available': gemini_result.get('available', False) if gemini_result else False,
        'gemini_success': gemini_result.get('success', False) if gemini_result else False,
        'checks': checks,
    }

    if extra:
        result.update(extra)

    return result
