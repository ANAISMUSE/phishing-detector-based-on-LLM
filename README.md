# phishing-detector-based-on-LLM

基于 **FastAPI/Flask + LLM（DeepSeek）+ 规则引擎** 的钓鱼邮件检测系统，可识别**传统钓鱼、AI 生成钓鱼、混合型钓鱼**三类攻击，面向邮件安全 / 安全运营（SecOps）场景。

> 本项目经一轮深度重构：统一了此前缺失的邮件数据模型、让 5 维特征真正跑通、补全了 SPF/DKIM/DMARC 邮件鉴权、提供了可离线运行的评测框架，并去掉了对 NLTK 的运行时依赖。

---

## 核心能力

- **5 维特征提取**：URL（短链 / 裸 IP / 高风险 TLD / 品牌诱骗）、发件人（Reply-To / Return-Path 不一致）、正文内容、语言学（停用词多样性、紧迫/诱导话术）、HTML（隐藏文本 / 伪装链接）。
- **规则引擎 + LLM 双路融合**：规则加权打分（阈值判定）+ LLM 结构化判定，最终以 **OR 合并、置信度取 max**，并区分 `Traditional / AI-Generated / Hybrid` 攻击类型。
- **SPF / DKIM / DMARC 鉴权**：基于 `dnspython` 做真实 DNS 查询（SPF 记录解析、DKIM 选择器探测、DMARC 策略读取），结果缺失时优雅降级。
- **可独立调用的核心逻辑**：检测核心不依赖 Flask，`analyze_with_llm` 通过 `llm_func` 注入 LLM，便于单元测试（离线 mock）。
- **REST API**：新增 `/api/v1/analyze`（JSON 入参，支持原始 RFC822 文本或 base64 编码 .eml）+ `/health` 健康检查，便于接入 SOAR / 邮件网关。
- **Web UI / PWA**：前端单页上传 `.eml/.txt`，结果可视化（AJAX，不依赖服务端模板渲染）。

---

## 系统架构

```
app/
├── routes.py            # 路由：/  ·  /health  ·  /analyze(文件)  ·  /api/v1/analyze(JSON)
├── utils/
│   ├── email_parser.py   # 规范化邮件数据模型（body.plain/html、headers、DKIM/Auth-Results）
│   ├── feature_extractor.py  # 5 维特征（正则分词，无 NLTK）
│   ├── auth_checks.py    # SPF / DKIM / DMARC 真实 DNS 鉴权
│   ├── detection.py      # 规则引擎 + LLM 融合 + 攻击类型判定
│   └── engine.py         # run_analysis：串联解析→特征→鉴权→检测，输出统一 JSON
eval/
├── samples.json         # 手工标注「测试夹具」（非真实基准）
└── benchmark.py         # Precision / Recall / F1 / 误报率（默认离线，--llm 接 DeepSeek）
tests/                   # pytest：parser / feature / auth / detection / engine（mock LLM）
```

数据流：`邮件(.eml/文本) → email_parser → feature_extractor → [auth_checks] → detection(规则+LLM) → engine 汇总 → JSON 判定`

---

## 快速开始

```bash
# 1) 依赖（Python 3.11+）
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) 运行（离线规则模式无需 API key）
export DEEPSEEK_API_KEY=""      # 留空 = 仅规则模式
python run.py                   # http://localhost:5000

# 3) 可选：接入 DeepSeek 提升 AI 生成钓鱼识别
export DEEPSEEK_API_KEY="sk-xxx"
```

Docker：

```bash
docker build -t phishing-detector .
docker run -p 5000:5000 -e DEEPSEEK_API_KEY=sk-xxx phishing-detector
```

---

## REST API

`POST /api/v1/analyze`

```jsonc
// 请求
{ "email": "From: support@paypa1-secure.com\nTo: a@b.com\nSubject: 紧急验证\n\n点击 http://paypa1-secure.com/login 验证" }
// 或 base64 编码的 .eml
{ "email": "<base64>", "encoding": "base64" }

// 响应
{
  "is_phishing": true,
  "attack_type": "Traditional Phishing",
  "confidence": 0.95,
  "score": 105,
  "reasons": ["Found 1 suspicious URLs", "..."],
  "auth": { "spf": "...", "dkim": "...", "dmarc": "..." }  // DNS 不可达时为 null
}
```

---

## 评测

内置 `eval/benchmark.py` 在标注样例上计算指标。**默认离线（仅规则引擎）**，无需 API key / 网络：

```bash
python eval/benchmark.py                 # 规则-only
python eval/benchmark.py --llm          # 接 DeepSeek（需 DEEPSEEK_API_KEY）
python eval/benchmark.py --samples your_dataset.json
```

> ⚠️ **诚实声明**：`eval/samples.json` 是手工构造的**测试夹具**，仅用于演示指标计算流程，**不**代表真实世界性能。对外报告 P/R/F1 前，请用 PhishTank / Nazario / Enron-Spam 等公开数据集替换 `samples.json` 并复测。

---

## 安全岗位相关技术亮点

- **邮件鉴权落地**：真实 DNS 查询 SPF/DKIM/DMARC，而非仅做关键词匹配——对应邮件安全的核心防御手段。
- **提示注入 / 对抗鲁棒性**：双路融合降低对单一 LLM 的信任；规则引擎在模型失效时仍可独立判定。
- **可观测 / 可集成**：REST API + 健康检查，可直接对接 SIEM / SOAR 编排。
- **工程健壮性**：核心逻辑可测试、依赖精简（去 NLTK）、离线评测闭环。

---

## 已知局限（Roadmap）

- [ ] 用公开基准（PhishTank 等）替换夹具并报告真实指标。
- [ ] 对抗样本 / 提示注入专项测试集。
- [ ] 模型微调或本地小模型（降低 API 依赖与延迟）。
- [ ] 批量 API 与速率限制、API key 轮换。
