import requests
import json
import time
from flask import current_app

def detect_phishing(email_content, features):
    """使用特征和LLM分析检测钓鱼邮件"""
    # 基于规则的分析
    rule_based_result = rule_based_analysis(features)
    
    # LLM分析
    llm_analysis = analyze_with_llm(email_content, features)
    
    # 混合分析结果
    final_result = {
        'is_phishing': rule_based_result['is_phishing'] or llm_analysis['is_phishing'],
        'confidence': max(rule_based_result['confidence'], llm_analysis['confidence']),
        'rule_based_analysis': rule_based_result,
        'llm_analysis': llm_analysis,
        'attack_type': determine_attack_type(rule_based_result, llm_analysis)
    }
    
    return final_result

def rule_based_analysis(features):
    """基于规则的钓鱼邮件分析"""
    score = 0
    reasons = []
    
    # URL分析
    suspicious_urls = sum(1 for url in features['urls'] if url['suspicious'])
    url_mismatches = sum(1 for url in features['urls'] if url['mismatch'])
    
    if suspicious_urls > 0:
        score += suspicious_urls * 15
        reasons.append(f"Found {suspicious_urls} suspicious URLs")
    
    if url_mismatches > 0:
        score += url_mismatches * 20
        reasons.append(f"Found {url_mismatches} URL text mismatches")
    
    # 发件人分析
    if features['sender_analysis']['mismatch']:
        score += 25
        reasons.append("Sender email address mismatch detected")
    
    if features['sender_analysis']['spoofing_indicators']:
        score += len(features['sender_analysis']['spoofing_indicators']) * 15
        reasons.append(f"Sender spoofing indicators: {', '.join(features['sender_analysis']['spoofing_indicators'])}")
    
    # 内容分析
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
    
    # HTML特征
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
        reasons.append(f"HTML obfuscation techniques: {', '.join(html_features['obfuscation_techniques'])}")
    
    # 紧急程度评分
    if features['urgency_score']['level'] == 'High':
        score += 15
        reasons.append("High urgency tone detected")
    elif features['urgency_score']['level'] == 'Medium':
        score += 7
        reasons.append("Medium urgency tone detected")
    
    # 最终评分和结果
    is_phishing = score >= 50
    confidence = min(score / 100, 0.95) if is_phishing else max(0.05, (100 - score) / 100)
    
    result = {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'score': score,
        'reasons': reasons
    }
    
    return result

def analyze_with_llm(email_content, features):
    """使用DeepSeek LLM进行钓鱼邮件分析"""
    # 准备邮件内容摘要
    subject = email_content['headers'].get('Subject', 'No Subject')
    sender = email_content['headers'].get('From', 'Unknown Sender')
    body = email_content['body']['plain'][:3000] if email_content['body']['plain'] else 'No body content'
    
    # 构建提示
    prompt = f"""Analyze this email for phishing indicators. Consider advanced techniques and AI-generated content.

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

Analyze whether this is a phishing email, and if so, indicate what type it is (traditional phishing, AI-generated phishing, or a hybrid attack). Provide your confidence level (0.0-1.0) and key reasons for your determination. Return only a valid JSON object with these fields: "is_phishing" (boolean), "confidence" (float), "attack_type" (string), "reasons" (array of strings), "ai_indicators" (array of strings).
"""

    # 调用DeepSeek API
    try:
        api_key = current_app.config['DEEPSEEK_API_KEY']
        model = current_app.config['DEEPSEEK_MODEL']
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        data = {
            "model": model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": 1000
        }
        
        response = requests.post(
            "https://api.deepseek.com/v1/chat/completions",
            headers=headers,
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            llm_response = result['choices'][0]['message']['content']
            
            # 解析JSON响应
            try:
                analysis = json.loads(llm_response)
                return {
                    'is_phishing': analysis.get('is_phishing', False),
                    'confidence': analysis.get('confidence', 0.0),
                    'attack_type': analysis.get('attack_type', 'Unknown'),
                    'reasons': analysis.get('reasons', []),
                    'ai_indicators': analysis.get('ai_indicators', [])
                }
            except json.JSONDecodeError:
                # 如果LLM没有返回有效的JSON，使用备用处理
                return fallback_llm_analysis(llm_response)
        else:
            # API请求失败
            return {
                'is_phishing': False,
                'confidence': 0.0,
                'attack_type': 'Unknown (API Error)',
                'reasons': [f"API Error: {response.status_code}"],
                'ai_indicators': []
            }
    except Exception as e:
        return {
            'is_phishing': False,
            'confidence': 0.0,
            'attack_type': 'Unknown (Error)',
            'reasons': [f"Error: {str(e)}"],
            'ai_indicators': []
        }

def fallback_llm_analysis(response_text):
    """当LLM返回的不是有效JSON时的备用分析"""
    is_phishing = 'phishing' in response_text.lower() and 'not phishing' not in response_text.lower()
    
    # 简单估计置信度
    confidence_indicators = [
        ('highly confident', 0.9),
        ('high confidence', 0.85),
        ('confident', 0.8),
        ('likely', 0.7),
        ('possibly', 0.6),
        ('may be', 0.55),
        ('uncertain', 0.5),
        ('unlikely', 0.3),
        ('not likely', 0.2)
    ]
    
    confidence = 0.5  # 默认值
    for indicator, value in confidence_indicators:
        if indicator in response_text.lower():
            confidence = value
            break
    
    # 确定攻击类型
    attack_type = 'Unknown'
    if 'traditional phishing' in response_text.lower():
        attack_type = 'Traditional Phishing'
    elif 'ai-generated' in response_text.lower() or 'ai generated' in response_text.lower():
        attack_type = 'AI-Generated Phishing'
    elif 'hybrid' in response_text.lower():
        attack_type = 'Hybrid Attack'
    
    # 提取原因 (简单方法)
    reasons = []
    lines = response_text.split('\n')
    for line in lines:
        if line.strip().startswith('-') or line.strip().startswith('*'):
            reasons.append(line.strip()[1:].strip())
    
    # 如果没有找到列表项，尝试提取句子
    if not reasons:
        sentences = response_text.split('.')
        for sentence in sentences:
            if 'suspicious' in sentence.lower() or 'concern' in sentence.lower() or 'indicator' in sentence.lower():
                clean_sentence = sentence.strip()
                if clean_sentence:
                    reasons.append(clean_sentence)
    
    # 如果仍然没有找到原因，使用全文
    if not reasons:
        reasons = [response_text[:100] + "..."]
    
    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'attack_type': attack_type,
        'reasons': reasons[:5],  # 限制原因数量
        'ai_indicators': []
    }

def determine_attack_type(rule_based_result, llm_analysis):
    """确定攻击类型（传统、AI生成或混合）"""
    if not rule_based_result['is_phishing'] and not llm_analysis['is_phishing']:
        return "Not Phishing"
    
    # 使用LLM的攻击类型如果有的话
    if 'attack_type' in llm_analysis and llm_analysis['attack_type'] not in ['Unknown', 'Unknown (Error)', 'Unknown (API Error)']:
        return llm_analysis['attack_type']
    
    # 使用规则推断攻击类型
    traditional_indicators = rule_based_result['score'] >= 30
    ai_indicators = len(llm_analysis.get('ai_indicators', [])) > 0
    
    if traditional_indicators and ai_indicators:
        return "Hybrid Attack"
    elif ai_indicators:
        return "AI-Generated Phishing"
    else:
        return "Traditional Phishing"
