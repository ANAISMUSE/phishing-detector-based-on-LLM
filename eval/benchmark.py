#!/usr/bin/env python
# eval/benchmark.py
"""钓鱼检测评测脚本：在标注样例集上计算 Precision / Recall / F1 / 误报率。

默认离线（仅规则引擎，无需 API key / 网络），便于本地快速验证管线。
使用真实 LLM 时加 --llm（需设置环境变量 DEEPSEEK_API_KEY）。

注意：内置 samples.json 是手工构造的「测试夹具」，仅用于演示指标计算，
      不代表真实世界性能。请用 PhishTank / Nazario / Enron-Spam 等公开数据集
      替换后，再对外报告 P/R/F1 数字。

用法：
    python eval/benchmark.py
    python eval/benchmark.py --llm
    python eval/benchmark.py --samples path/to/your_dataset.json
"""
import os
import sys
import json
import argparse

# 让脚本可从仓库根目录运行
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.utils.email_parser import parse_email_string
from app.utils.engine import run_analysis


def make_llm_func():
    """若设置 DEEPSEEK_API_KEY 则构造真实 LLM 调用，否则返回 None（仅规则）。"""
    api_key = os.environ.get('DEEPSEEK_API_KEY', '')
    if not api_key:
        return None
    from app.utils.detection import deepseek_llm_call
    model = os.environ.get('MODEL_NAME', 'deepseek-chat')
    api_base = os.environ.get('DEEPSEEK_API_BASE', 'https://api.deepseek.com')

    def _call(prompt: str) -> str:
        return deepseek_llm_call(prompt, api_key, model, api_base)

    return _call


def evaluate(samples, llm_func):
    tp = fp = tn = fn = 0
    per_type = {}  # attack_type -> {tp,fp,tn,fn}
    rows = []

    for s in samples:
        label_phish = (s.get('label') == 'phishing')
        try:
            email_data = parse_email_string(s['raw'])
            res = run_analysis(email_data, llm_func)
            pred_phish = bool(res.get('is_phishing'))
        except Exception as e:
            print(f"[WARN] {s.get('id')} 解析/分析失败: {e}")
            pred_phish = False
            res = {}

        if pred_phish and label_phish:
            tp += 1
        elif pred_phish and not label_phish:
            fp += 1
        elif not pred_phish and not label_phish:
            tn += 1
        else:
            fn += 1

        at = s.get('attack_type', 'unknown')
        bucket = per_type.setdefault(at, {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0})
        if pred_phish and label_phish:
            bucket['tp'] += 1
        elif pred_phish and not label_phish:
            bucket['fp'] += 1
        elif not pred_phish and not label_phish:
            bucket['tn'] += 1
        else:
            bucket['fn'] += 1

        rows.append((s.get('id'), 'PHISH' if label_phish else 'legit',
                     'PHISH' if pred_phish else 'legit',
                     res.get('attack_type', '-'), res.get('confidence', '-'),
                     'OK' if pred_phish == label_phish else 'MISS'))

    return {
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'per_type': per_type, 'rows': rows,
    }


def _metric(num, den):
    return round(num / den, 3) if den else 0.0


def report(stats, use_llm):
    total = stats['tp'] + stats['fp'] + stats['tn'] + stats['fn']
    tp, fp, tn, fn = stats['tp'], stats['fp'], stats['tn'], stats['fn']
    precision = _metric(tp, tp + fp)
    recall = _metric(tp, tp + fn)
    f1 = _metric(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    fp_rate = _metric(fp, fp + tn)
    accuracy = _metric(tp + tn, total)

    print("=" * 78)
    print(f"Phishing Detection Benchmark  |  mode: {'LLM+Rule' if use_llm else 'Rule-only'}")
    print("=" * 78)
    print(f"{'ID':<12}{'LABEL':<8}{'PRED':<8}{'ATTACK_TYPE':<18}{'CONF':<8}{'RESULT'}")
    print("-" * 78)
    for r in stats['rows']:
        print(f"{r[0]:<12}{r[1]:<8}{r[2]:<8}{str(r[3]):<18}{str(r[4]):<8}{r[5]}")
    print("-" * 78)
    print(f"Samples     : {total}")
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Accuracy   : {accuracy}")
    print(f"Precision  : {precision}")
    print(f"Recall     : {recall}")
    print(f"F1         : {f1}")
    print(f"FalsePos%  : {fp_rate}")
    print("=" * 78)

    if stats['per_type']:
        print("Per attack-type (phishing subset):")
        for at, b in stats['per_type'].items():
            p = _metric(b['tp'], b['tp'] + b['fp'])
            r = _metric(b['tp'], b['tp'] + b['fn'])
            print(f"  {at:<14} precision={p}  recall={r}  (tp={b['tp']} fp={b['fp']} fn={b['fn']})")
        print("=" * 78)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', default=os.path.join(ROOT, 'eval', 'samples.json'))
    ap.add_argument('--llm', action='store_true', help='使用 DeepSeek LLM（需 DEEPSEEK_API_KEY）')
    args = ap.parse_args()

    with open(args.samples, 'r', encoding='utf-8') as f:
        data = json.load(f)

    samples = data['samples']
    llm_func = make_llm_func() if args.llm else None
    if args.llm and llm_func is None:
        print("[WARN] 已指定 --llm 但未检测到 DEEPSEEK_API_KEY，回退到仅规则模式。")

    stats = evaluate(samples, llm_func)
    report(stats, use_llm=bool(llm_func))


if __name__ == '__main__':
    main()
