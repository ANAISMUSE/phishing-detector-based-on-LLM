# app/utils/feature_extractor.py
"""从规范化邮件数据中提取 5 维特征：URL / 发件人 / 正文内容 / 语言学 / HTML。

不依赖 NLTK：语言学特征使用轻量正则分词，降低部署体积、去除运行时下载。
输入约定：email_content 由 email_parser.parse_email* 产出（body.plain / body.html / headers）。
"""
import re
from typing import List
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# 简单英文停用词（用于词汇多样性计算，避免引入 NLTK）
_STOPWORDS = {
    'a', 'an', 'the', 'and', 'or', 'but', 'if', 'then', 'else', 'of', 'to', 'in',
    'on', 'at', 'by', 'for', 'with', 'about', 'as', 'into', 'like', 'through', 'after',
    'over', 'between', 'out', 'against', 'during', 'without', 'before', 'under', 'around',
    'among', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
    'do', 'does', 'did', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she',
    'it', 'we', 'they', 'my', 'your', 'his', 'her', 'its', 'our', 'their', 'me', 'him',
    'us', 'them', 'what', 'which', 'who', 'whom', 'where', 'when', 'why', 'how', 'all',
    'any', 'both', 'each', 'few', 'more', 'most', 'some', 'such', 'no', 'nor', 'not',
    'only', 'own', 'same', 'so', 'than', 'too', 'very', 'can', 'will', 'just', 'should',
    'now', 'from', 'your', 'please', 'thank', 'thanks', 'dear', 'hello', 'hi',
}

_TOKEN_RE = re.compile(r"[A-Za-z']+")


def _tokenize(text: str) -> List[str]:
    """轻量分词：仅保留字母/撇号 token，转小写。"""
    return _TOKEN_RE.findall(text.lower())


def extract_features(email_content):
    """从邮件内容中提取特征。"""
    features = {
        'urls': extract_urls(email_content),
        'sender_analysis': analyze_sender(email_content),
        'content_analysis': analyze_content(email_content),
        'linguistic_features': extract_linguistic_features(email_content),
        'html_features': extract_html_features(email_content),
        'urgency_score': calculate_urgency_score(email_content),
    }
    return features


def extract_urls(email_content):
    """提取并分析邮件中的 URL（来自 HTML 与纯文本）。"""
    html_content = email_content['body']['html']
    text_content = email_content['body']['plain']

    urls = []

    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            url = a_tag['href']
            visible_text = a_tag.get_text().strip()
            urls.append({
                'url': url,
                'visible_text': visible_text,
                'mismatch': is_url_text_mismatch(url, visible_text),
                'domain': urlparse(url).netloc,
                'suspicious': is_suspicious_url(url),
            })

    if text_content:
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
        for url in re.findall(url_pattern, text_content):
            if url not in [u['url'] for u in urls]:
                urls.append({
                    'url': url,
                    'visible_text': '',
                    'mismatch': False,
                    'domain': urlparse(url).netloc,
                    'suspicious': is_suspicious_url(url),
                })

    return urls


def is_url_text_mismatch(url, visible_text):
    """检查 URL 与可见文本是否不匹配（潜在钓鱼指标）。"""
    if not visible_text or visible_text.isspace():
        return False

    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
    text_urls = re.findall(url_pattern, visible_text)

    if text_urls:
        for text_url in text_urls:
            if url != text_url and urlparse(url).netloc != urlparse(text_url).netloc:
                return True

    common_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook',
                     'instagram', 'netflix', 'bank', 'wellsfargo', 'chase', 'citibank']

    url_domain = urlparse(url).netloc.lower()
    for brand in common_brands:
        if brand in visible_text.lower() and brand not in url_domain:
            return True

    return False


def is_suspicious_url(url):
    """检查 URL 是否具有可疑特征（主机名感知，避免误伤官方域名）。"""
    url = url or ''
    # 1) 短链 / 裸 IP 地址 / 高风险 TLD
    if re.search(r'(bit\.ly|tinyurl\.com|is\.gd|t\.co)', url, re.IGNORECASE):
        return True
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        return True
    if re.search(r'\.(tk|xyz|top)$', url, re.IGNORECASE):
        return True

    # 2) 品牌诱骗：主机名含品牌词但注册域并非官方域名
    try:
        host = urlparse(url).netloc.lower().split(':')[0]
    except Exception:
        host = url.lower()
    if host:
        official = {
            'paypal': 'paypal.com', 'apple': 'apple.com', 'microsoft': 'microsoft.com',
            'amazon': 'amazon.com', 'google': 'google.com', 'facebook': 'facebook.com',
        }
        for brand, official_domain in official.items():
            if brand in host and host != official_domain and not host.endswith('.' + official_domain):
                return True
        # 3) 子域/主机名中的通用敏感词（如 secure-login、account.verify）
        if re.search(r'(secure|account|login|verify|update|bank)(?=\.|-)', host):
            return True

    return False


def analyze_sender(email_content):
    """分析发件人信息是否可疑（含 Reply-To / Return-Path 不一致）。"""
    headers = email_content['headers']
    from_header = headers.get('From', '')
    reply_to = headers.get('Reply-To', '')
    return_path = headers.get('Return-Path', '')

    sender_analysis = {
        'from': from_header,
        'reply_to': reply_to,
        'return_path': return_path,
        'mismatch': False,
        'spoofing_indicators': [],
    }

    if '<' in from_header and '>' in from_header:
        email_part = from_header.split('<')[1].split('>')[0]
        from_domain = email_part.split('@')[1].lower() if '@' in email_part else ''
    else:
        from_domain = from_header.split('@')[1].lower() if '@' in from_header else ''

    if reply_to and '@' in reply_to and from_domain:
        reply_domain = reply_to.split('@')[1].lower().rstrip('>') if '@' in reply_to else ''
        if reply_domain and from_domain != reply_domain:
            sender_analysis['mismatch'] = True
            sender_analysis['spoofing_indicators'].append(
                f"Reply-To domain ({reply_domain}) doesn't match From domain ({from_domain})")

    if return_path and '@' in return_path:
        return_domain = return_path.split('@')[1].lower().rstrip('>') if '@' in return_path else ''
        if return_domain and from_domain and from_domain != return_domain:
            sender_analysis['mismatch'] = True
            sender_analysis['spoofing_indicators'].append(
                f"Return-Path domain ({return_domain}) doesn't match From domain ({from_domain})")

    suspicious_patterns = [
        (r'paypal.*\.com(?!\.paypal\.com)', 'Possible PayPal spoofing'),
        (r'apple.*\.com(?!\.apple\.com)', 'Possible Apple spoofing'),
        (r'amazon.*\.com(?!\.amazon\.com)', 'Possible Amazon spoofing'),
        (r'microsoft.*\.com(?!\.microsoft\.com)', 'Possible Microsoft spoofing'),
        (r'google.*\.com(?!\.google\.com)', 'Possible Google spoofing'),
        (r'facebook.*\.com(?!\.facebook\.com)', 'Possible Facebook spoofing'),
        (r'instagram.*\.com(?!\.instagram\.com)', 'Possible Instagram spoofing'),
        (r'netflix.*\.com(?!\.netflix\.com)', 'Possible Netflix spoofing'),
        (r'bank.*\.com', 'Generic bank domain'),
        (r'secure.*\.com', 'Suspicious "secure" domain'),
        (r'.*-secure-.*\.com', 'Suspicious hyphenated "secure" domain'),
    ]

    if from_domain:
        for pattern, message in suspicious_patterns:
            if re.match(pattern, from_domain, re.IGNORECASE):
                sender_analysis['spoofing_indicators'].append(message)

    return sender_analysis


def analyze_content(email_content):
    """分析邮件正文的可疑特征。"""
    subject = email_content['headers'].get('Subject', '')
    text = email_content['body']['plain']

    content_analysis = {
        'sensitive_keywords': [],
        'urgency_indicators': [],
        'suspicious_requests': [],
        'threat_indicators': [],
        'subject_suspicious': False,
    }

    sensitive_keywords = [
        'password', 'account', 'login', 'verify', 'update', 'confirm', 'secure',
        'unusual activity', 'suspicious activity', 'security alert', 'verify your account',
        'account suspended', 'limited access', 'unauthorized', 'click here',
    ]
    urgency_indicators = [
        'urgent', 'immediately', 'important', 'alert', 'warning', 'attention',
        'within 24 hours', 'expire', 'termination', 'suspended', 'blocked',
        'required action', 'time sensitive', 'act now', 'promptly',
    ]
    suspicious_requests = [
        'provide your', 'confirm your', 'update your', 'verify your',
        'click the link', 'click on the link', 'follow the link',
        'open the attachment', 'download the attachment',
        'enable macros', 'enter your', 'login details',
    ]
    threat_indicators = [
        'account will be terminated', 'account will be suspended',
        'unauthorized access', 'security breach', 'compromised account',
        'legal action', 'overdue payment', 'failed to pay', 'collection agency',
        'law enforcement',
    ]

    subject_lower = subject.lower()
    for keyword in sensitive_keywords + urgency_indicators:
        if keyword.lower() in subject_lower:
            content_analysis['subject_suspicious'] = True
            break

    text_lower = text.lower()
    for keyword in sensitive_keywords:
        if keyword.lower() in text_lower:
            content_analysis['sensitive_keywords'].append(keyword)
    for phrase in urgency_indicators:
        if phrase.lower() in text_lower:
            content_analysis['urgency_indicators'].append(phrase)
    for request in suspicious_requests:
        if request.lower() in text_lower:
            content_analysis['suspicious_requests'].append(request)
    for threat in threat_indicators:
        if threat.lower() in text_lower:
            content_analysis['threat_indicators'].append(threat)

    return content_analysis


def extract_linguistic_features(email_content):
    """提取语言学特征（无 NLTK，正则分词），可辅助识别 AI 生成文本。"""
    text = email_content['body']['plain']

    if not text:
        return {
            'language_complexity': 0,
            'grammar_issues': 0,
            'avg_sentence_length': 0,
            'vocabulary_diversity': 0,
            'formality_score': 0,
        }

    tokens = _tokenize(text)
    filtered = [w for w in tokens if w not in _STOPWORDS]

    sentences = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]

    avg_sentence_length = len(tokens) / len(sentences) if sentences else 0
    vocabulary_diversity = len(set(filtered)) / len(filtered) if filtered else 0
    avg_word_length = sum(len(w) for w in filtered) / len(filtered) if filtered else 0

    formal_indicators = ['therefore', 'thus', 'consequently', 'furthermore', 'moreover',
                         'however', 'nevertheless', 'regarding', 'concerning', 'accordingly']
    formality_score = sum(1 for w in filtered if w in formal_indicators) / len(filtered) if filtered else 0

    grammar_patterns = [r'\bthey is\b', r'\bhe have\b', r'\bshe have\b', r'\bi is\b', r'\byou is\b']
    grammar_issues = sum(len(re.findall(p, text, re.IGNORECASE)) for p in grammar_patterns)

    return {
        'language_complexity': round(avg_word_length, 3),
        'grammar_issues': grammar_issues,
        'avg_sentence_length': round(avg_sentence_length, 2),
        'vocabulary_diversity': round(vocabulary_diversity, 3),
        'formality_score': round(formality_score, 3),
    }


def extract_html_features(email_content):
    """提取 HTML 相关特征，检测隐藏内容与混淆技术。"""
    html_content = email_content['body']['html']

    if not html_content:
        return {
            'hidden_content': False,
            'invisible_text': False,
            'script_tags': 0,
            'obfuscation_techniques': [],
            'form_fields': 0,
        }

    soup = BeautifulSoup(html_content, 'html.parser')

    hidden_elements = soup.select(
        '[style*="display: none"], [style*="display:none"], '
        '[style*="visibility: hidden"], [style*="visibility:hidden"], [hidden]')

    invisible_text_elements = []
    for tag in soup.find_all(['div', 'span', 'p']):
        style = tag.get('style', '')
        if (('color:#fff' in style or 'color: #fff' in style or 'color:white' in style or 'color: white' in style)
                and ('background:#fff' in style or 'background: #fff' in style or 'background:white' in style or 'background: white' in style)):
            invisible_text_elements.append(tag)

    script_tags = soup.find_all('script')

    obfuscation_techniques = []
    if '&#' in html_content and html_content.count('&#') > 20:
        obfuscation_techniques.append('Excessive HTML entity encoding')
    if re.search(r'data:.*?;base64,', html_content):
        obfuscation_techniques.append('Base64 encoded content')
    if re.search(r'\\u[0-9a-fA-F]{4}', html_content):
        obfuscation_techniques.append('Unicode escape sequences')

    form_fields = len(soup.find_all(['input', 'textarea', 'select']))

    return {
        'hidden_content': len(hidden_elements) > 0,
        'invisible_text': len(invisible_text_elements) > 0,
        'script_tags': len(script_tags),
        'obfuscation_techniques': obfuscation_techniques,
        'form_fields': form_fields,
    }


def calculate_urgency_score(email_content):
    """计算邮件的紧急程度分数。"""
    subject = email_content['headers'].get('Subject', '')
    text = email_content['body']['plain']

    urgency_terms = [
        'urgent', 'immediately', 'important', 'alert', 'warning', 'attention',
        'within 24 hours', 'expire', 'termination', 'suspended', 'blocked',
        'required action', 'time sensitive', 'act now', 'promptly',
        'limited time', 'deadline', 'final notice', 'last chance', 'action required',
    ]

    subject_score = sum(1 for term in urgency_terms if term.lower() in subject.lower())

    text_score = 0
    for term in urgency_terms:
        text_score += text.lower().count(term.lower())

    words = len(text.split())
    normalized_text_score = (text_score / words * 100) if words > 0 else 0

    total_score = subject_score * 2 + normalized_text_score

    if total_score > 10:
        urgency_level = "High"
    elif total_score > 5:
        urgency_level = "Medium"
    else:
        urgency_level = "Low"

    return {
        'score': round(total_score, 2),
        'level': urgency_level,
    }
