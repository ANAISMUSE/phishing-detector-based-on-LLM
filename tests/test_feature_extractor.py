# tests/test_feature_extractor.py
from app.utils.feature_extractor import (
    extract_features, is_suspicious_url, is_url_text_mismatch, calculate_urgency_score,
)


def _email(plain='', html='', subject='', from_='', reply_to='', return_path=''):
    return {
        'headers': {'Subject': subject, 'From': from_, 'Reply-To': reply_to, 'Return-Path': return_path},
        'body': {'plain': plain, 'html': html},
    }


def test_extract_features_keys():
    feats = extract_features(_email(plain='hello world'))
    for k in ('urls', 'sender_analysis', 'content_analysis', 'linguistic_features', 'html_features', 'urgency_score'):
        assert k in feats


def test_suspicious_url_detection():
    assert is_suspicious_url('http://192.168.1.1/login')
    assert is_suspicious_url('http://paypa1-secure.com')
    assert not is_suspicious_url('https://www.paypal.com')


def test_url_text_mismatch():
    assert is_url_text_mismatch('http://evil.com', 'paypal.com')
    assert not is_url_text_mismatch('http://paypal.com', 'paypal.com')


def test_sender_replyto_mismatch():
    feats = extract_features(_email(
        from_='a@bank.com', reply_to='a@evil.com', return_path='a@evil.com'))
    assert feats['sender_analysis']['mismatch'] is True
    assert len(feats['sender_analysis']['spoofing_indicators']) > 0


def test_urgency_high():
    u = calculate_urgency_score(_email(
        subject='Urgent action required',
        plain='Within 24 hours your account will be terminated. Act now.'))
    assert u['level'] == 'High'


def test_no_nltk_import():
    # 确保 feature_extractor 不依赖 nltk
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith('nltk'):
            raise ImportError('nltk should not be imported')
        return real_import(name, *a, **k)

    builtins.__import__ = fake_import
    try:
        extract_features(_email(plain='test sentence. another one.'))
    finally:
        builtins.__import__ = real_import
