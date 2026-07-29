# tests/test_detection.py
import json
from app.utils.feature_extractor import extract_features
from app.utils.detection import (
    rule_based_analysis, analyze_with_llm, determine_attack_type, deepseek_llm_call,
)


def _phishing_email():
    return {
        'headers': {
            'Subject': 'Urgent: verify your account',
            'From': 'security@paypa1-secure.com',
            'Reply-To': 'fraud@evil.xyz',
        },
        'body': {
            'plain': 'Your account will be suspended within 24 hours. Click the link to verify your password immediately.',
            'html': '',
        },
    }


def test_rule_based_flags_phishing():
    feats = extract_features(_phishing_email())
    rule = rule_based_analysis(feats)
    assert rule['is_phishing'] is True
    assert rule['score'] >= 50


def test_determine_attack_type():
    rule = {'is_phishing': True, 'score': 70}
    llm = {'attack_type': 'Traditional Phishing', 'ai_indicators': []}
    assert determine_attack_type(rule, llm) == 'Traditional Phishing'


def test_analyze_with_llm_mock():
    email = _phishing_email()
    feats = extract_features(email)
    fake_json = json.dumps({
        'is_phishing': True, 'confidence': 0.92,
        'attack_type': 'Traditional Phishing',
        'reasons': ['spoofed sender'], 'ai_indicators': [],
    })

    def llm_func(prompt):
        return fake_json

    res = analyze_with_llm(email, feats, llm_func)
    assert res['is_phishing'] is True
    assert res['attack_type'] == 'Traditional Phishing'


def test_analyze_with_llm_none_falls_back():
    email = _phishing_email()
    feats = extract_features(email)
    res = analyze_with_llm(email, feats, None)
    assert res['attack_type'] == 'Unknown (LLM disabled)'


def test_deepseek_call_requires_key():
    try:
        deepseek_llm_call('prompt', '')
        assert False, 'should raise without key'
    except RuntimeError:
        pass
