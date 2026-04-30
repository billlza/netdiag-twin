# NetDiag Twin 演示说明（短报告）

## What-if 示例

Current path: `loss = 4%`, `latency = 120ms`, diagnosis = `congestion`  
What-if: `reroute to path B`  
Expected:

- loss = `2.2%`（↓45%）
- latency = `90ms`（↓25%）
- QoE risk = `low`

建议操作仅输出为建议，需人工审批：`Need human approval: yes`。

## 可交付清单

- 项目源码与 6 页 Streamlit 应用
- 证据字段 JSON schema
- 场景样本 Trace（6 类）
- 测试（unit + integration）
- 可复现环境文件（`requirements*`, `setup_env.sh`）
