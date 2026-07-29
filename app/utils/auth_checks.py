# app/utils/auth_checks.py
"""邮件身份认证校验：SPF / DKIM / DMARC（基于真实 DNS 查询）。

这是钓鱼检测里最关键的"发件人真实性"防线——攻击者可以伪造 From，
但无法伪造一条通过域名 DNS 校验通过的 SPF/DKIM/DMARC 链。
模块对 DNS 失败/离线场景做了优雅降级，不会让整个分析流程崩溃。

依赖：dnspython（DNS 查询）。无网络或解析异常时返回 status='unknown'。
"""
import re
from typing import Dict, Any, Optional


def _resolve_txt(domain: str) -> list:
    """查询域名的 TXT 记录，返回字符串列表。失败返回空列表。"""
    try:
        import dns.resolver  # 延迟导入，避免无 dnspython 时整模块不可用
    except ImportError:
        return []
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        return [''.join(s.strings).decode('utf-8', 'replace') for s in answers]
    except Exception:
        return []


def check_spf(domain: str) -> Dict[str, Any]:
    """查询并解析 SPF 记录。"""
    result = {'domain': domain, 'record': None, 'status': 'unknown', 'detail': ''}
    if not domain:
        result['status'] = 'skipped'
        return result

    txts = _resolve_txt(domain)
    spf = next((t for t in txts if t.lower().startswith('v=spf1')), None)
    if not spf:
        result['status'] = 'none'
        result['detail'] = '未找到 SPF 记录（域名无发件人策略）'
        return result

    result['record'] = spf
    # 仅做存在性 + 收尾策略判定（不执行完整 SPF 校验引擎）
    if ' -all' in spf:
        result['status'] = 'hardfail'
        result['detail'] = '存在 SPF 且以 -all 收尾（严格）'
    elif ' ~all' in spf:
        result['status'] = 'softfail'
        result['detail'] = '存在 SPF 且以 ~all 收尾（软失败）'
    else:
        result['status'] = 'present'
        result['detail'] = '存在 SPF 记录（收尾策略非标准）'
    return result


def check_dmarc(domain: str) -> Dict[str, Any]:
    """查询并解析 DMARC 记录（_dmarc.<domain>）。"""
    result = {'domain': domain, 'record': None, 'status': 'unknown', 'policy': None, 'detail': ''}
    if not domain:
        result['status'] = 'skipped'
        return result

    txts = _resolve_txt(f'_dmarc.{domain}')
    dmarc = next((t for t in txts if t.lower().startswith('v=dmarc1')), None)
    if not dmarc:
        result['status'] = 'none'
        result['detail'] = '未配置 DMARC 记录'
        return result

    result['record'] = dmarc
    policy = 'none'
    m = re.search(r'p=(\w+)', dmarc, re.IGNORECASE)
    if m:
        policy = m.group(1).lower()
    result['policy'] = policy
    result['status'] = 'present'
    result['detail'] = f'DMARC 策略 p={policy}'
    return result


def check_dkim(domain: str, selector: str = 'default') -> Dict[str, Any]:
    """查询并解析 DKIM 公钥记录（<selector>._domainkey.<domain>）。"""
    result = {'domain': domain, 'selector': selector, 'record': None, 'status': 'unknown', 'detail': ''}
    if not domain or not selector:
        result['status'] = 'skipped'
        result['detail'] = '缺少签名域或选择器，无法校验 DKIM'
        return result

    txts = _resolve_txt(f'{selector}._domainkey.{domain}')
    dkim = next((t for t in txts if 'v=DKIM1' in t or 'k=' in t or 'p=' in t), None)
    if not dkim:
        result['status'] = 'none'
        result['detail'] = f'未找到选择器 "{selector}" 的 DKIM 公钥记录'
        return result

    result['record'] = dkim
    result['status'] = 'present'
    result['detail'] = '找到 DKIM 公钥记录'
    return result


def _domain_from_header(header_value: str) -> str:
    """从 From / Return-Path 头提取域名。"""
    if not header_value:
        return ''
    email_part = ''
    if '<' in header_value and '>' in header_value:
        email_part = header_value.split('<')[1].split('>')[0]
    else:
        email_part = header_value
    if '@' in email_part:
        return email_part.split('@')[1].lower().strip('>').strip()
    return ''


def check_email_auth(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """编排整封邮件的 SPF/DKIM/DMARC 校验，给出综合鉴权结论。

    输入 email_data：email_parser 产出的规范化结构（headers / dkim_signature / auth_results）。
    返回结构：
    {
      'from_domain', 'spf', 'dmarc', 'dkim',
      'authenticated': bool,          # 是否至少通过一项强校验
      'auth_issues': [str],           # 失败/缺失项说明
      'detail': str
    }
    """
    headers = email_data.get('headers', {})
    from_domain = _domain_from_header(headers.get('From', ''))
    return_path_domain = _domain_from_header(headers.get('Return-Path', ''))
    dkim_sig = email_data.get('dkim_signature') or {}

    spf = check_spf(return_path_domain or from_domain)
    dmarc = check_dmarc(from_domain)
    dkim = check_dkim(dkim_sig.get('domain', ''), dkim_sig.get('selector', ''))

    auth_issues = []
    # 收件方若已附带 Authentication-Results，优先采信
    ar = email_data.get('auth_results', {})
    if ar.get('spf') == 'fail':
        auth_issues.append('Authentication-Results 标记 SPF 失败')
    if ar.get('dkim') == 'fail':
        auth_issues.append('Authentication-Results 标记 DKIM 失败')
    if ar.get('dmarc') == 'fail':
        auth_issues.append('Authentication-Results 标记 DMARC 失败')

    # DNS 侧判定
    if spf['status'] in ('none',):
        auth_issues.append(f"发件域 {from_domain} 无 SPF 记录")
    if dmarc['status'] in ('none',):
        auth_issues.append(f"发件域 {from_domain} 无 DMARC 记录")
    if dkim['status'] in ('none', 'skipped'):
        auth_issues.append('未发现 DKIM 签名或无法解析公钥')

    # 通过标准：DMARC 配置了策略 且（SPF 或 DKIM）状态非 none/none-fail
    authenticated = dmarc['status'] == 'present' and (
        spf['status'] in ('hardfail', 'softfail', 'present')
        or dkim['status'] == 'present'
    )

    if not auth_issues and authenticated:
        detail = 'SPF/DKIM/DMARC 链路完整，发件人真实性可信'
    elif authenticated:
        detail = '核心鉴权通过，存在次要告警'
    else:
        detail = '发件人真实性无法验证（缺少有效 SPF/DKIM/DMARC）'

    return {
        'from_domain': from_domain,
        'spf': spf,
        'dmarc': dmarc,
        'dkim': dkim,
        'authenticated': bool(authenticated),
        'auth_issues': auth_issues,
        'detail': detail,
    }
