# app/utils/engine.py
"""统一分析引擎：串联 特征提取 -> 规则+LLM 融合 -> 邮件鉴权，输出最终判定。

对外只暴露 run_analysis()，返回结构同时兼容：
  - 前端 AJAX（is_phishing / confidence / attack_type / threat_level / indicators / details）
  - REST API（附带 features / auth_results / rule_based_analysis / llm_analysis 详情）
"""
from app.utils.feature_extractor import extract_features
from app.utils.detection import (
    rule_based_analysis, analyze_with_llm, determine_attack_type,
)
from app.utils.auth_checks import check_email_auth


def _threat_level(is_phishing, rule, llm):
    if not is_phishing:
        return 'Low'
    if rule['score'] >= 70 or llm['confidence'] >= 0.8:
        return 'High'
    return 'Medium'


def run_analysis(email_data: dict, llm_func=None) -> dict:
    """执行完整分析管线。

    email_data: email_parser 产出的规范化结构
    llm_func: 可选，注入 LLM 调用（prompt -> text）；为 None 时进入仅规则模式
    """
    features = extract_features(email_data)
    rule = rule_based_analysis(features)
    llm = analyze_with_llm(email_data, features, llm_func)
    auth = check_email_auth(email_data)

    is_phishing = bool(rule['is_phishing'] or llm['is_phishing'])
    attack_type = determine_attack_type(rule, llm)
    threat_level = _threat_level(is_phishing, rule, llm)
    confidence = round(max(rule['confidence'], llm['confidence']), 3)

    # 鉴权结论融入风险说明：未通过 SPF/DKIM/DMARC 的发件人真实性存疑
    indicators = list(rule['reasons'][:5])
    if auth['auth_issues']:
        indicators += [f"[Auth] {issue}" for issue in auth['auth_issues']]
    indicators = indicators[:10]

    details = _build_details(rule, llm, auth, attack_type, is_phishing)

    return {
        # 前端 AJAX 契约字段
        'success': True,
        'is_phishing': is_phishing,
        'confidence': confidence,
        'attack_type': attack_type,
        'threat_level': threat_level,
        'indicators': indicators,
        'details': details,
        'analysis': details,
        # REST API 详情字段
        'score': rule['score'],
        'reasons': rule['reasons'],
        'features': _safe_features(features),
        'auth_results': auth,
        'rule_based_analysis': rule,
        'llm_analysis': llm,
    }


def _safe_features(features: dict) -> dict:
    """去除不可序列化/冗余内容，便于 JSON 返回。"""
    f = dict(features)
    # 完整 body 体积大，前端用不到，剔除
    f.pop('urls', None)
    return f


def _build_details(rule, llm, auth, attack_type, is_phishing) -> str:
    verdict = "钓鱼邮件 (Phishing)" if is_phishing else "疑似正常邮件 (Legitimate)"
    lines = [
        f"判定：{verdict}",
        f"攻击类型：{attack_type}",
        f"规则引擎得分：{rule['score']}/100",
        f"LLM 置信度：{llm['confidence']}",
        f"邮件鉴权：{'通过' if auth['authenticated'] else '未通过/缺失'} —— {auth['detail']}",
    ]
    if rule['reasons']:
        lines.append("规则命中：" + "; ".join(rule['reasons'][:3]))
    if llm.get('reasons'):
        lines.append("LLM 研判：" + "; ".join(llm['reasons'][:3]))
    return "\n".join(lines)
