# tests/test_engine.py
import json
from app.utils.email_parser import parse_email_string
from app.utils.engine import run_analysis


PHISH = """From: security@paypa1-secure.com
To: user@example.com
Subject: Urgent: Verify your PayPal account now
Reply-To: fraud@evil.xyz
Date: Mon, 28 Jul 2026 09:00:00 +0000

Your account will be suspended within 24 hours. Click the link to verify your password immediately: http://paypa1-secure.com/login
"""

LEGIT = """From: alice@friend.com
To: bob@example.com
Subject: Lunch tomorrow?

Hey Bob, are you free for lunch around noon?
"""


def test_engine_flags_phishing_with_llm():
    def llm_func(prompt):
        return json.dumps({
            'is_phishing': True, 'confidence': 0.95,
            'attack_type': 'Traditional Phishing',
            'reasons': ['spoofed PayPal domain'], 'ai_indicators': [],
        })

    data = parse_email_string(PHISH)
    res = run_analysis(data, llm_func)
    assert res['is_phishing'] is True
    assert res['attack_type'] == 'Traditional Phishing'
    assert res['threat_level'] in ('High', 'Medium')
    assert 'auth_results' in res and 'features' in res
    # 前端 AJAX 契约字段存在
    for k in ('is_phishing', 'confidence', 'attack_type', 'threat_level', 'indicators', 'details'):
        assert k in res


def test_engine_rule_only_mode():
    data = parse_email_string(LEGIT)
    res = run_analysis(data, None)  # 无 LLM
    assert res['success'] is True
    assert res['is_phishing'] is False
    assert res['threat_level'] == 'Low'
