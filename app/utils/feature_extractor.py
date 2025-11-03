import re
from urllib.parse import urlparse
import hashlib
from bs4 import BeautifulSoup
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

# 确保NLTK资源已下载
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')

def extract_features(email_content):
    """从邮件内容中提取特征"""
    features = {
        'urls': extract_urls(email_content),
        'sender_analysis': analyze_sender(email_content),
        'content_analysis': analyze_content(email_content),
        'linguistic_features': extract_linguistic_features(email_content),
        'html_features': extract_html_features(email_content),
        'urgency_score': calculate_urgency_score(email_content)
    }
    return features

def extract_urls(email_content):
    """提取并分析邮件中的URL"""
    html_content = email_content['body']['html']
    text_content = email_content['body']['plain']
    
    urls = []
    
    # 从HTML中提取URL
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
                'suspicious': is_suspicious_url(url)
            })
    
    # 从文本中提取URL
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
    if text_content:
        for url in re.findall(url_pattern, text_content):
            if url not in [u['url'] for u in urls]:
                urls.append({
                    'url': url,
                    'visible_text': '',
                    'mismatch': False,
                    'domain': urlparse(url).netloc,
                    'suspicious': is_suspicious_url(url)
                })
    
    return urls

def is_url_text_mismatch(url, visible_text):
    """检查URL和可见文本是否不匹配（潜在的钓鱼指标）"""
    if not visible_text or visible_text.isspace():
        return False
    
    # 检查可见文本中是否包含一个不同的URL
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
    text_urls = re.findall(url_pattern, visible_text)
    
    if text_urls:
        for text_url in text_urls:
            if url != text_url and urlparse(url).netloc != urlparse(text_url).netloc:
                return True
    
    # 检查可见文本是否为知名品牌，但URL不包含该品牌
    common_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 
                     'instagram', 'netflix', 'bank', 'wellsfargo', 'chase', 'citibank']
    
    url_domain = urlparse(url).netloc.lower()
    for brand in common_brands:
        if brand in visible_text.lower() and brand not in url_domain:
            return True
    
    return False

def is_suspicious_url(url):
    """检查URL是否具有可疑特征"""
    suspicious_indicators = [
        r'bit\.ly', r'tinyurl\.com', r'is\.gd', r't\.co',  # 短网址
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP地址
        r'\.tk$', r'\.xyz$', r'\.top$',  # 可疑TLD
        r'paypal.*\.com(?!\.paypal\.com)',  # 品牌伪装
        r'secure.*\.com', r'account.*\.com',  # 常见钓鱼词汇
        r'-secure-', r'-account-', r'-login-',  # 连字符分隔
    ]
    
    for pattern in suspicious_indicators:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    
    return False

def analyze_sender(email_content):
    """分析发件人信息是否可疑"""
    headers = email_content['headers']
    from_header = headers.get('From', '')
    reply_to = headers.get('Reply-To', '')
    return_path = headers.get('Return-Path', '')
    
    sender_analysis = {
        'from': from_header,
        'reply_to': reply_to,
        'return_path': return_path,
        'mismatch': False,
        'spoofing_indicators': []
    }
    
    # 提取发件人域名
    from_domain = ''
    if '<' in from_header and '>' in from_header:
        email_part = from_header.split('<')[1].split('>')[0]
        if '@' in email_part:
            from_domain = email_part.split('@')[1].lower()
    
    # 检查Reply-To与From是否不匹配
    if reply_to and '@' in reply_to and '@' in from_header:
        reply_domain = reply_to.split('@')[1].lower() if '@' in reply_to else ''
        if from_domain and reply_domain and from_domain != reply_domain:
            sender_analysis['mismatch'] = True
            sender_analysis['spoofing_indicators'].append(f"Reply-To domain ({reply_domain}) doesn't match From domain ({from_domain})")
    
    # 检查Return-Path与From是否不匹配
    if return_path and '@' in return_path:
        return_domain = return_path.split('@')[1].lower().rstrip('>') if '@' in return_path else ''
        if from_domain and return_domain and from_domain != return_domain:
            sender_analysis['mismatch'] = True
            sender_analysis['spoofing_indicators'].append(f"Return-Path domain ({return_domain}) doesn't match From domain ({from_domain})")
    
    # 检查常见的伪造发件人模式
    if from_domain:
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
        
        for pattern, message in suspicious_patterns:
            if re.match(pattern, from_domain, re.IGNORECASE):
                sender_analysis['spoofing_indicators'].append(message)
    
    return sender_analysis

def analyze_content(email_content):
    """分析邮件内容的可疑特征"""
    subject = email_content['headers'].get('Subject', '')
    text = email_content['body']['plain']
    
    content_analysis = {
        'sensitive_keywords': [],
        'urgency_indicators': [],
        'suspicious_requests': [],
        'threat_indicators': [],
        'subject_suspicious': False
    }
    
    # 检查可疑关键词
    sensitive_keywords = [
        'password', 'account', 'login', 'verify', 'update', 'confirm', 'secure',
        'unusual activity', 'suspicious activity', 'security alert', 'verify your account',
        'account suspended', 'limited access', 'unauthorized', 'click here'
    ]
    
    urgency_indicators = [
        'urgent', 'immediately', 'important', 'alert', 'warning', 'attention',
        'within 24 hours', 'expire', 'termination', 'suspended', 'blocked',
        'required action', 'time sensitive', 'act now', 'promptly'
    ]
    
    suspicious_requests = [
        'provide your', 'confirm your', 'update your', 'verify your',
        'click the link', 'click on the link', 'follow the link',
        'open the attachment', 'download the attachment',
        'enable macros', 'enter your', 'login details'
    ]
    
    threat_indicators = [
        'account will be terminated', 'account will be suspended',
        'unauthorized access', 'security breach', 'compromised account',
        'legal action', 'overdue payment', 'failed to pay', 'collection agency',
        'law enforcement'
    ]
    
    # 检查主题行
    subject_lower = subject.lower()
    for keyword in sensitive_keywords + urgency_indicators:
        if keyword.lower() in subject_lower:
            content_analysis['subject_suspicious'] = True
            break
    
    # 检查邮件正文
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
    """提取语言学特征，可以识别LLM生成的内容"""
    text = email_content['body']['plain']
    
    # 确保有内容可分析
    if not text:
        return {
            'language_complexity': 0,
            'grammar_issues': 0,
            'avg_sentence_length': 0,
            'vocabulary_diversity': 0,
            'formality_score': 0
        }
    
    # 分词
    tokens = word_tokenize(text.lower())
    
    # 移除停用词
    stop_words = set(stopwords.words('english'))
    filtered_tokens = [word for word in tokens if word.isalnum() and word not in stop_words]
    
    # 句子
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if s.strip()]
    
    # 计算特征
    avg_sentence_length = len(tokens) / len(sentences) if sentences else 0
    vocabulary_diversity = len(set(filtered_tokens)) / len(filtered_tokens) if filtered_tokens else 0
    
    # 计算语言复杂度（使用平均词长作为简单指标）
    avg_word_length = sum(len(word) for word in filtered_tokens) / len(filtered_tokens) if filtered_tokens else 0
    
    # 形式化程度（使用形式化语言指标）
    formal_indicators = ['therefore', 'thus', 'consequently', 'furthermore', 'moreover',
                        'however', 'nevertheless', 'regarding', 'concerning', 'accordingly']
    formality_score = sum(1 for word in filtered_tokens if word in formal_indicators) / len(filtered_tokens) if filtered_tokens else 0
    
    # 语法问题（简单估计 - 仅用作示例）
    grammar_patterns = [r'\bthey is\b', r'\bhe have\b', r'\bshe have\b', r'\bi is\b', r'\byou is\b']
    grammar_issues = sum(len(re.findall(pattern, text, re.IGNORECASE)) for pattern in grammar_patterns)
    
    return {
        'language_complexity': avg_word_length,
        'grammar_issues': grammar_issues,
        'avg_sentence_length': avg_sentence_length,
        'vocabulary_diversity': vocabulary_diversity,
        'formality_score': formality_score
    }

def extract_html_features(email_content):
    """提取HTML相关特征，检测隐藏内容和混淆技术"""
    html_content = email_content['body']['html']
    
    if not html_content:
        return {
            'hidden_content': False,
            'invisible_text': False,
            'script_tags': 0,
            'obfuscation_techniques': [],
            'form_fields': 0
        }
    
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 检查隐藏内容
    hidden_elements = soup.select('[style*="display: none"], [style*="display:none"], [style*="visibility: hidden"], [style*="visibility:hidden"], [hidden]')
    
    # 检查不可见文本（颜色与背景相同）
    invisible_text_elements = []
    for tag in soup.find_all(['div', 'span', 'p']):
        style = tag.get('style', '')
        if ('color:#fff' in style or 'color: #fff' in style or 'color:white' in style or 'color: white' in style) and \
           ('background:#fff' in style or 'background: #fff' in style or 'background:white' in style or 'background: white' in style):
            invisible_text_elements.append(tag)
    
    # 检查脚本标签
    script_tags = soup.find_all('script')
    
    # 检查混淆技术
    obfuscation_techniques = []
    
    # 检查HTML实体编码过度使用
    if '&#' in html_content and html_content.count('&#') > 20:
        obfuscation_techniques.append('Excessive HTML entity encoding')
    
    # 检查Base64编码内容
    base64_pattern = r'data:.*?;base64,'
    if re.search(base64_pattern, html_content):
        obfuscation_techniques.append('Base64 encoded content')
    
    # 检查Unicode转义序列
    unicode_pattern = r'\\u[0-9a-fA-F]{4}'
    if re.search(unicode_pattern, html_content):
        obfuscation_techniques.append('Unicode escape sequences')
    
    # 检查表单字段
    form_fields = len(soup.find_all(['input', 'textarea', 'select']))
    
    return {
        'hidden_content': len(hidden_elements) > 0,
        'invisible_text': len(invisible_text_elements) > 0,
        'script_tags': len(script_tags),
        'obfuscation_techniques': obfuscation_techniques,
        'form_fields': form_fields
    }

def calculate_urgency_score(email_content):
    """计算邮件的紧急程度分数"""
    subject = email_content['headers'].get('Subject', '')
    text = email_content['body']['plain']
    
    # 紧急词汇和短语
    urgency_terms = [
        'urgent', 'immediately', 'important', 'alert', 'warning', 'attention',
        'within 24 hours', 'expire', 'termination', 'suspended', 'blocked',
        'required action', 'time sensitive', 'act now', 'promptly',
        'limited time', 'deadline', 'final notice', 'last chance', 'action required'
    ]
    
    # 计算主题中的紧急词汇
    subject_score = sum(1 for term in urgency_terms if term.lower() in subject.lower())
    
    # 计算正文中的紧急词汇频率
    text_score = 0
    for term in urgency_terms:
        text_score += text.lower().count(term.lower())
    
    # 正文长度标准化
    words = len(text.split())
    normalized_text_score = (text_score / words * 100) if words > 0 else 0
    
    # 计算总分
    total_score = subject_score * 2 + normalized_text_score
    
    # 评级
    if total_score > 10:
        urgency_level = "High"
    elif total_score > 5:
        urgency_level = "Medium"
    else:
        urgency_level = "Low"
    
    return {
        'score': total_score,
        'level': urgency_level
    }
