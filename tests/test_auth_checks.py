# tests/test_auth_checks.py
import app.utils.auth_checks as ac


def _patch(txt_map):
    """替换 _resolve_txt 为返回预设 TXT 记录的函数。"""
    def fake(domain):
        return txt_map.get(domain, [])
    ac._resolve_txt = fake


def test_spf_present_hardfail():
    _patch({'example.com': ['v=spf1 include:_spf.google.com -all']})
    r = ac.check_spf('example.com')
    assert r['status'] == 'hardfail'
    assert 'v=spf1' in r['record']


def test_spf_none():
    _patch({})
    r = ac.check_spf('example.com')
    assert r['status'] == 'none'


def test_dmarc_policy():
    _patch({'_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']})
    r = ac.check_dmarc('example.com')
    assert r['status'] == 'present'
    assert r['policy'] == 'reject'


def test_dkim_present():
    _patch({'selector1._domainkey.example.com': ['v=DKIM1; k=rsa; p=MIIBIjANBgkqh']})
    r = ac.check_dkim('example.com', 'selector1')
    assert r['status'] == 'present'


def test_check_email_auth_authenticated():
    _patch({
        'example.com': ['v=spf1 -all'],
        '_dmarc.example.com': ['v=DMARC1; p=quarantine'],
    })
    email_data = {
        'headers': {'From': 'a@example.com', 'Return-Path': 'a@example.com'},
        'dkim_signature': {'domain': 'example.com', 'selector': 'sel'},
        'auth_results': {},
    }
    r = ac.check_email_auth(email_data)
    assert r['authenticated'] is True
    assert r['from_domain'] == 'example.com'


def test_check_email_auth_unauthenticated():
    _patch({})  # 无任何 DNS 记录
    email_data = {
        'headers': {'From': 'a@unknown-domain.xyz'},
        'dkim_signature': None,
        'auth_results': {},
    }
    r = ac.check_email_auth(email_data)
    assert r['authenticated'] is False
    assert len(r['auth_issues']) > 0
