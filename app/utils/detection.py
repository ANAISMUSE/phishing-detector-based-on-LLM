# app/utils/detection.py
"""检测核心：规则引擎 + LLM 双路融合，判定钓鱼并区分攻击类型。

设计目标：核心逻辑不依赖 Flask，LLM 调用通过 llm_func 注入，便于单元测试
（测试中传入 mock 即可，无需真实 API key / 网络）。
"""
import json


# ---------------------------------------------------------------------------
# 规则引擎
# ---------------------------------------------------------------------------
def rule_based_analysis(features):
    """基于规则的钓鱼邮件打分（纯函数）。"""
    score = 0
    reasons = []

    suspicious_urls = sum(1 for url in features['urls'] if url['suspicious'])
    url_mismatches = sum(1 for url in features['urls'] if url['mismatch'])

    if suspicious_urls > 0:
        score += suspicious_urls * 15
        reasons.append(f"Found {suspicious_urls} suspicious URLs")

    if url_mismatches > 0:
        score += url_mismatches * 20
        reasons.append(f"Found {url_mismatches} URL text mismatches")

    if features['sender_analysis']['mismatch']:
        score += 25
        reasons.append("Sender email address mismatch detected")

    if features['sender_analysis']['spoofing_indicators']:
        score += len(features['sender_analysis']['spoofing_indicators']) * 15
        reasons.append(
            f"Sender spoofing indicators: {', '.join(features['sender_analysis']['spoofing_indicators'])}")

    content = features['content_analysis']

    if content['subject_suspicious']:
        score += 10
        reasons.append("Suspicious subject line")

    if len(content['sensitive_keywords']) > 0:
        score += min(len(content['sensitive_keywords']) * 5, 20)
        reasons.append(f"Sensitive keywords found: {', '.join(content['sensitive_keywords'][:5])}")

    if len(content['urgency_indicators']) > 0:
        score += min(len(content['urgency_indicators']) * 5, 20)
        reasons.append(f"Urgency indicators found: {', '.join(content['urgency_indicators'][:5])}")

    if len(content['suspicious_requests']) > 0:
        score += min(len(content['suspicious_requests']) * 8, 25)
        reasons.append(f"Suspicious requests found: {', '.join(content['suspicious_requests'][:5])}")

    if len(content['threat_indicators']) > 0:
        score += min(len(content['threat_indicators']) * 8, 25)
        reasons.append(f"Threat indicators found: {', '.join(content['threat_indicators'][:5])}")

    html_features = features['html_features']

    if html_features['hidden_content']:
        score += 15
        reasons.append("Hidden content detected in HTML")

    if html_features['invisible_text']:
        score += 20
        reasons.append("Invisible text detected (text color same as background)")

    if html_features['script_tags'] > 0:
        score += min(html_features['script_tags'] * 5, 15)
        reasons.append(f"Found {html_features['script_tags']} script tags")

    if html_features['form_fields'] > 0:
        score += min(html_features['form_fields'] * 5, 15)
        reasons.append(f"Found {html_features['form_fields']} form input fields")

    if html_features['obfuscation_techniques']:
        score += len(html_features['obfuscation_techniques']) * 10
        reasons.append(
            f"HTML obfuscation techniques: {', '.join(html_features['obfuscation_techniques'])}")

    if features['urgency_score']['level'] == 'High':
        score += 15
        reasons.append("High urgency tone detected")
    elif features['urgency_score']['level'] == 'Medium':
        score += 7
        reasons.append("Medium urgency tone detected")

    is_phishing = score >= 50
    confidence = min(score / 100, 0.95) if is_phishing else max(0.05, (100 - score) / 100)

    return {
        'is_phishing': is_phishing,
        'confidence': round(confidence, 3),
        'score': score,
        'reasons': reasons,
    }


# ---------------------------------------------------------------------------
# LLM 分析
# ---------------------------------------------------------------------------
def build_llm_prompt(email_content, features):
    """构造发送给 LLM 的分析提示。"""
    subject = email_content['headers'].get('Subject', 'No Subject')
    sender = email_content['headers'].get('From', 'Unknown Sender')
    body = email_content['body']['plain'][:3000] if email_content['body']['plain'] else 'No body content'

    return f"""Analyze this email for phishing indicators. Consider advanced techniques and AI-generated content.

SUBJECT: {subject}
FROM: {sender}
BODY:
{body}

Key Features Detected:
- Suspicious URLs: {sum(1 for url in features['urls'] if url['suspicious'])}
- URL text mismatches: {sum(1 for url in features['urls'] if url['mismatch'])}
- Sender email mismatch: {"Yes" if features['sender_analysis']['mismatch'] else "No"}
- Sender spoofing indicators: {len(features['sender_analysis']['spoofing_indicators'])}
- Sensitive keywords: {len(features['content_analysis']['sensitive_keywords'])}
- Urgency indicators: {len(features['content_analysis']['urgency_indicators'])}
- Suspicious requests: {len(features['content_analysis']['suspicious_requests'])}
- Threat indicators: {len(features['content_analysis']['threat_indicators'])}
- HTML obfuscation: {len(features['html_features']['obfuscation_techniques']) > 0}
- Form fields present: {features['html_features']['form_fields'] > 0}
- Linguistic formality score: {features['linguistic_features'].get('formality_score', 0)}

Analyze whether this is a phishing email, and if so, indicate what type it is (traditional phishing, AI-generated phishing, or a hybrid attack). Provide your confidence level (0.0-1.0) and key reasons for your determination. Return only a valid JSON object with these fields: "is_phishing" (boolean), "confidence" (float), "attack_type" (string), "reasons" (array of strings), "ai_indicators" (array of strings).
"""


def analyze_with_llm(email_content, features, llm_func=None):
    """使用 LLM 分析邮件。llm_func(prompt) -> str（由调用方注入，便于测试/切换模型）。"""
    prompt = build_llm_prompt(email_content, features)

    if llm_func is None:
        # 无 LLM 后端：降级为仅规则引擎结果
        return {
            'is_phishing': False,
            'confidence': 0.0,
            'attack_type': 'Unknown (LLM disabled)',
            'reasons': ['LLM backend unavailable; rule-only mode'],
            'ai_indicators': [],
        }

    try:
        llm_response = llm_func(prompt)
        return _parse_llm_json(llm_response)
    except Exception as e:
        return {
            'is_phishing': False,
            'confidence': 0.0,
            'attack_type': 'Unknown (Error)',
            'reasons': [f"Error: {str(e)}"],
            'ai_indicators': [],
        }


def _parse_llm_json(llm_response: str) -> dict:
    """解析 LLM 返回的 JSON，失败时降级为文本启发式解析。"""
    try:
        analysis = json.loads(llm_response)
        return {
            'is_phishing': bool(analysis.get('is_phishing', False)),
            'confidence': float(analysis.get('confidence', 0.0)),
            'attack_type': analysis.get('attack_type', 'Unknown'),
            'reasons': analysis.get('reasons', []),
            'ai_indicators': analysis.get('ai_indicators', []),
        }
    except (json.JSONDecodeError, TypeError, ValueError):
        return fallback_llm_analysis(llm_response)


def fallback_llm_analysis(response_text):
    """当 LLM 返回非有效 JSON 时的备用解析。"""
    is_phishing = 'phishing' in response_text.lower() and 'not phishing' not in response_text.lower()

    confidence_indicators = [
        ('highly confident', 0.9), ('high confidence', 0.85), ('confident', 0.8),
        ('likely', 0.7), ('possibly', 0.6), ('may be', 0.55), ('uncertain', 0.5),
        ('unlikely', 0.3), ('not likely', 0.2),
    ]
    confidence = 0.5
    for indicator, value in confidence_indicators:
        if indicator in response_text.lower():
            confidence = value
            break

    attack_type = 'Unknown'
    low = response_text.lower()
    if 'traditional phishing' in low:
        attack_type = 'Traditional Phishing'
    elif 'ai-generated' in low or 'ai generated' in low:
        attack_type = 'AI-Generated Phishing'
    elif 'hybrid' in low:
        attack_type = 'Hybrid Attack'

    reasons = []
    for line in response_text.split('\n'):
        if line.strip().startswith('-') or line.strip().startswith('*'):
            reasons.append(line.strip()[1:].strip())

    if not reasons:
        for sentence in response_text.split('.'):
            if any(k in sentence.lower() for k in ('suspicious', 'concern', 'indicator')):
                if sentence.strip():
                    reasons.append(sentence.strip())

    if not reasons:
        reasons = [response_text[:100] + "..."]

    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'attack_type': attack_type,
        'reasons': reasons[:5],
        'ai_indicators': [],
    }


def determine_attack_type(rule_based_result, llm_analysis):
    """确定攻击类型（传统 / AI 生成 / 混合）。"""
    if not rule_based_result['is_phishing'] and not llm_analysis['is_phishing']:
        return "Not Phishing"

    at = llm_analysis.get('attack_type', 'Unknown')
    if at not in ['Unknown', 'Unknown (Error)', 'Unknown (API Error)', 'Unknown (LLM disabled)']:
        return at

    traditional_indicators = rule_based_result['score'] >= 30
    ai_indicators = len(llm_analysis.get('ai_indicators', [])) > 0

    if traditional_indicators and ai_indicators:
        return "Hybrid Attack"
    elif ai_indicators:
        return "AI-Generated Phishing"
    else:
        return "Traditional Phishing"


# ---------------------------------------------------------------------------
# DeepSeek 后端（供 routes 注入）
# ---------------------------------------------------------------------------
def deepseek_llm_call(prompt: str, api_key: str, model: str = 'deepseek-chat',
                      api_base: str = 'https://api.deepseek.com') -> str:
    """调用 DeepSeek Chat Completion，返回模型文本。"""
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY 未配置")

    import requests

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    data = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 1000,
    }
    resp = requests.post(f"{api_base}/v1/chat/completions", headers=headers, json=data, timeout=30)
    if resp.status_code == 200:
        return resp.json()['choices'][0]['message']['content']
    raise RuntimeError(f"DeepSeek API error: {resp.status_code}")
