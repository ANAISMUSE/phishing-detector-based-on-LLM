# app/utils/analyzer.py
from typing import Dict, Any, List
import requests
import json
from flask import current_app
import traceback

def analyze_email(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """使用DeepSeek LLM分析邮件"""
    
    print("\n" + "=" * 60)
    print("🔍 开始分析邮件")
    print("=" * 60)
    
    try:
        # 1. 构建prompt
        print("📝 构建分析prompt...")
        prompt = build_analysis_prompt(email_data)
        print(f"Prompt长度: {len(prompt)} 字符")
        print(f"Prompt前100字符: {prompt[:100]}...")
        
        # 2. 调用API
        print("\n🌐 调用DeepSeek API...")
        llm_result = call_deepseek_api(prompt)
        print(f"✓ API返回结果长度: {len(llm_result)} 字符")
        print(f"返回内容预览: {llm_result[:200]}...")
        
        # 3. 解析结果
        print("\n📊 解析LLM响应...")
        analysis = parse_llm_response(llm_result)
        print(f"解析结果: {json.dumps(analysis, ensure_ascii=False, indent=2)}")
        
        # 4. 规则检查
        print("\n🔎 执行规则检查...")
        rule_indicators = rule_based_analysis(email_data)
        print(f"发现 {len(rule_indicators)} 个规则指标")
        
        # 5. 合并结果
        print("\n🔀 合并分析结果...")
        final_result = merge_analysis(analysis, rule_indicators)
        
        print("\n✓ 分析完成!")
        print("=" * 60 + "\n")
        
        return final_result
        
    except Exception as e:
        print(f"\n❌ 分析失败: {str(e)}")
        print("错误堆栈:")
        traceback.print_exc()
        print("=" * 60 + "\n")
        raise Exception(f"分析失败: {str(e)}")

def build_analysis_prompt(email_data: Dict[str, Any]) -> str:
    """构建分析prompt"""
    print("  - 提取邮件主题、发件人等信息...")
    
    prompt = f"""你是一个专业的网络安全专家，专门分析钓鱼邮件。请分析以下邮件并判断是否为钓鱼邮件。

邮件信息：
- 主题: {email_data.get('subject', 'N/A')}
- 发件人: {email_data.get('from', 'N/A')}
- 收件人: {email_data.get('to', 'N/A')}
- 回复地址: {email_data.get('reply_to', 'N/A')}

邮件正文：
{email_data.get('body', 'N/A')[:1000]}

URLs:
{', '.join(email_data.get('urls', [])[:10])}

请分析：
1. 这是否是钓鱼邮件？
2. 攻击类型（Traditional/LLM-generated/Hybrid/None）
3. 威胁等级（High/Medium/Low）
4. 具体的可疑指标
5. 置信度（0-1之间的小数）

请以JSON格式回复：
{{
    "is_phishing": true/false,
    "attack_type": "Traditional/LLM-generated/Hybrid/None",
    "threat_level": "High/Medium/Low",
    "confidence": 0.0-1.0,
    "indicators": ["指标1", "指标2"],
    "reasoning": "详细分析说明"
}}"""
    
    return prompt

def call_deepseek_api(prompt: str) -> str:
    """调用DeepSeek API"""
    
    # 获取配置
    api_key = current_app.config.get('DEEPSEEK_API_KEY')
    api_base = current_app.config.get('DEEPSEEK_API_BASE')
    
    print(f"  - API Base: {api_base}")
    print(f"  - API Key: {api_key[:8]}..." if api_key else "  - ❌ API Key未设置!")
    
    if not api_key:
        raise Exception("DEEPSEEK_API_KEY未配置")
    
    url = f"{api_base}/v1/chat/completions"
    print(f"  - 请求URL: {url}")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": current_app.config.get('MODEL_NAME', 'deepseek-chat'),
        "messages": [
            {"role": "system", "content": "你是一个专业的网络安全分析专家。"},
            {"role": "user", "content": prompt}
        ],
        "temperature": current_app.config.get('TEMPERATURE', 0.7),
        "max_tokens": current_app.config.get('MAX_TOKENS', 2000)
    }
    
    print(f"  - 模型: {data['model']}")
    print(f"  - Temperature: {data['temperature']}")
    print(f"  - Max Tokens: {data['max_tokens']}")
    
    try:
        print("  - 发送请求...")
        response = requests.post(url, headers=headers, json=data, timeout=30)
        print(f"  - 状态码: {response.status_code}")
        
        response.raise_for_status()
        
        result = response.json()
        content = result['choices'][0]['message']['content']
        
        print(f"  - ✓ 成功获取响应")
        
        return content
        
    except requests.exceptions.RequestException as e:
        print(f"  - ❌ API调用失败: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"  - 错误详情: {e.response.text}")
        raise Exception(f"API调用失败: {str(e)}")

def parse_llm_response(response: str) -> Dict[str, Any]:
    """解析LLM响应"""
    print("  - 查找JSON内容...")
    
    try:
        json_start = response.find('{')
        json_end = response.rfind('}') + 1
        
        if json_start >= 0 and json_end > json_start:
            json_str = response[json_start:json_end]
            print(f"  - 提取的JSON: {json_str[:100]}...")
            parsed = json.loads(json_str)
            print("  - ✓ JSON解析成功")
            return parsed
        else:
            print("  - ⚠️ 未找到JSON格式，使用默认值")
            return {
                'is_phishing': False,
                'attack_type': 'None',
                'threat_level': 'Low',
                'confidence': 0.5,
                'indicators': [],
                'reasoning': response
            }
    except json.JSONDecodeError as e:
        print(f"  - ❌ JSON解析失败: {str(e)}")
        return {
            'is_phishing': False,
            'attack_type': 'None',
            'threat_level': 'Low',
            'confidence': 0.5,
            'indicators': [],
            'reasoning': '解析失败'
        }

def rule_based_analysis(email_data: Dict[str, Any]) -> List[str]:
    """基于规则的分析"""
    indicators = []
    
    sender = email_data.get('from', '').lower()
    if any(word in sender for word in ['noreply', 'no-reply', 'donotreply']):
        indicators.append("使用了无回复邮箱地址")
        print(f"  - 发现指标: 无回复邮箱")
    
    subject = email_data.get('subject', '').lower()
    suspicious_words = ['urgent', 'verify', 'suspended', 'unusual activity', 
                       'confirm', 'update', 'secure', 'account']
    for word in suspicious_words:
        if word in subject:
            indicators.append(f"主题包含可疑词汇: {word}")
            print(f"  - 发现指标: 可疑词汇 '{word}'")
    
    urls = email_data.get('urls', [])
    for url in urls:
        if 'bit.ly' in url or 'tinyurl' in url:
            indicators.append(f"使用了短链接: {url}")
            print(f"  - 发现指标: 短链接")
        if url.count('.') > 4:
            indicators.append(f"URL过长可疑: {url}")
            print(f"  - 发现指标: 可疑URL")
    
    body = email_data.get('body', '').lower()
    if 'click here' in body or 'click link' in body:
        indicators.append("包含'点击这里'类的诱导语句")
        print(f"  - 发现指标: 诱导语句")
    
    print(f"  - 总共发现 {len(indicators)} 个规则指标")
    return indicators

def merge_analysis(llm_analysis: Dict[str, Any], 
                  rule_indicators: List[str]) -> Dict[str, Any]:
    """合并分析结果"""
    
    all_indicators = llm_analysis.get('indicators', []) + rule_indicators
    
    if len(rule_indicators) >= 3 and llm_analysis.get('threat_level') == 'Low':
        llm_analysis['threat_level'] = 'Medium'
        print("  - 根据规则指标数量提升威胁等级")
    
    result = {
        'success': True,
        'is_phishing': llm_analysis.get('is_phishing', False),
        'confidence': llm_analysis.get('confidence', 0.5),
        'attack_type': llm_analysis.get('attack_type', 'None'),
        'threat_level': llm_analysis.get('threat_level', 'Low'),
        'indicators': list(set(all_indicators)),
        'details': llm_analysis.get('reasoning', ''),
        'analysis': llm_analysis.get('reasoning', ''),
        'llm_used': True
    }
    
    print(f"  - 最终置信度: {result['confidence']}")
    print(f"  - 威胁等级: {result['threat_level']}")
    print(f"  - 是否钓鱼: {result['is_phishing']}")
    
    return result
