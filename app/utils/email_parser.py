# app/utils/email_parser.py
"""邮件解析：将 .eml/.msg/.txt 解析为规范化数据结构。

统一的数据模型（供 feature_extractor / detection / auth_checks 共用）：
{
  'subject', 'from', 'to', 'date', 'reply_to', 'return_path', 'message_id',
  'headers': {header_name: header_value, ...},      # 全部原始头
  'body': {'plain': str, 'html': str},              # 明文与 HTML 正文
  'attachments': [{'filename', 'content_type'}],
  'dkim_signature': {'domain': str, 'selector': str} | None,
  'auth_results': {'spf': str, 'dkim': str, 'dmarc': str} | {},  # 来自 Authentication-Results
}
"""
import email
from email import policy
from email.parser import BytesParser
import re
from typing import Dict, List, Any, Optional

URL_RE = re.compile(
    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
)


def parse_email(filepath: str) -> Dict[str, Any]:
    """从文件路径解析邮件。"""
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return _build_email_data(msg)
    except Exception as e:
        raise Exception(f"解析邮件失败: {str(e)}")


def parse_email_string(raw: str) -> Dict[str, Any]:
    """从原始 RFC822 字符串解析邮件（供 REST API 使用）。"""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw.encode('utf-8', 'replace'))
        return _build_email_data(msg)
    except Exception as e:
        raise Exception(f"解析邮件失败: {str(e)}")


def _build_email_data(msg) -> Dict[str, Any]:
    email_data: Dict[str, Any] = {
        'subject': msg.get('subject', '') or '',
        'from': msg.get('from', '') or '',
        'to': msg.get('to', '') or '',
        'date': msg.get('date', '') or '',
        'reply_to': msg.get('reply-to', '') or '',
        'return_path': msg.get('return-path', '') or '',
        'message_id': msg.get('message-id', '') or '',
        'headers': dict(msg.items()),
        'body': {'plain': '', 'html': ''},
        'attachments': [],
        'dkim_signature': _parse_dkim_signature(msg.get('dkim-signature', '') or ''),
        'auth_results': _parse_auth_results(msg.get('authentication-results', '') or ''),
    }

    email_data['body'] = extract_body(msg)

    # 收集附件清单（不读取内容，仅记录元信息）
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            email_data['attachments'].append({
                'filename': part.get_filename() or 'unknown',
                'content_type': part.get_content_type(),
            })

    return email_data


def extract_body(msg) -> Dict[str, str]:
    """分别提取 plain / html 正文。"""
    plain_parts: List[str] = []
    html_parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            try:
                payload = part.get_content()
            except Exception:
                continue
            if content_type == 'text/plain':
                plain_parts.append(payload if isinstance(payload, str) else str(payload))
            elif content_type == 'text/html':
                html_parts.append(payload if isinstance(payload, str) else str(payload))
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            payload = str(msg.get_payload())
        if isinstance(payload, str):
            if content_type == 'text/html':
                html_parts.append(payload)
            else:
                plain_parts.append(payload)

    return {
        'plain': '\n'.join(plain_parts).strip(),
        'html': '\n'.join(html_parts).strip(),
    }


def extract_urls(text: str) -> List[str]:
    """从文本中提取 URL 并去重。"""
    if not text:
        return []
    return list(set(URL_RE.findall(text)))


def _parse_dkim_signature(header_value: str) -> Optional[Dict[str, str]]:
    """解析 DKIM-Signature 头，提取 d=(签名域) 与 s=(选择器)。"""
    if not header_value:
        return None
    tags = {}
    for token in header_value.split(';'):
        token = token.strip()
        if '=' not in token:
            continue
        k, v = token.split('=', 1)
        tags[k.strip()] = v.strip().strip('"')
    domain = tags.get('d')
    selector = tags.get('s')
    if domain and selector:
        return {'domain': domain, 'selector': selector}
    return None


def _parse_auth_results(header_value: str) -> Dict[str, str]:
    """解析 Authentication-Results 头，提取 spf/dkim/dmarc 判定。"""
    result: Dict[str, str] = {}
    if not header_value:
        return result
    for mechanism in ('spf', 'dkim', 'dmarc'):
        m = re.search(rf'{mechanism}=(\w+)', header_value, re.IGNORECASE)
        if m:
            result[mechanism] = m.group(1).lower()
    return result
