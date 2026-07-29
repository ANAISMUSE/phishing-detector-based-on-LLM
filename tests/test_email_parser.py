# tests/test_email_parser.py
from app.utils.email_parser import (
    parse_email_string, extract_urls, _parse_dkim_signature, _parse_auth_results,
)


SAMPLE = """From: Alice <alice@friend.com>
To: bob@example.com
Subject: Lunch tomorrow?
Reply-To: alice@friend.com
Return-Path: alice@friend.com
DKIM-Signature: v=1; a=rsa-sha256; d=friend.com; s=selector1; c=relaxed/simple; h=from:to:subject; bh=xxx; b=yyy
Authentication-Results: mx.example.com; spf=pass (example.com) smtp.mailfrom=alice@friend.com; dkim=pass header.d=friend.com; dmarc=pass header.from=friend.com
Content-Type: text/plain

Hey Bob, are you free for lunch around noon?

-- 
Alice
"""


def test_parse_basic_structure():
    data = parse_email_string(SAMPLE)
    assert data['subject'] == 'Lunch tomorrow?'
    assert 'alice@friend.com' in data['from']
    assert isinstance(data['headers'], dict)
    assert isinstance(data['body'], dict)
    assert 'Hey Bob' in data['body']['plain']


def test_dkim_signature_parsed():
    data = parse_email_string(SAMPLE)
    assert data['dkim_signature'] == {'domain': 'friend.com', 'selector': 'selector1'}


def test_auth_results_parsed():
    data = parse_email_string(SAMPLE)
    assert data['auth_results'].get('spf') == 'pass'
    assert data['auth_results'].get('dkim') == 'pass'
    assert data['auth_results'].get('dmarc') == 'pass'


def test_extract_urls():
    urls = extract_urls("visit https://a.com/x and http://b.org")
    assert 'https://a.com/x' in urls
    assert 'http://b.org' in urls


def test_parse_dkim_signature_missing():
    assert _parse_dkim_signature('') is None
    assert _parse_dkim_signature('v=1; d=only.com') is None  # 缺少 s=


def test_parse_auth_results_missing():
    assert _parse_auth_results('') == {}
