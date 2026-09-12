# NetDiag Twin 演示说明（短报告）

## What-if 示例

以下数值仅演示报告的表达方式，不是实测结果或固定预测。实际 what-if 结果来自
选定拓扑、输入证据和策略；操作效果须通过 before/after 遥测验证。

Current path: `loss = 4%`, `latency = 120ms`, diagnosis = `congestion`  
What-if: `reroute to path B`  
Expected:

- loss = `2.2%`（↓45%）
- latency = `90ms`（↓25%）
- QoE risk = `low`

建议操作仅输出为建议，需人工审批：`Need human approval: yes`。

## 可交付清单

- Rust 原生桌面应用（eframe/egui）与 CLI 源码
- 证据字段 JSON schema
- 场景样本 Trace（6 类）
- 测试（unit + integration）
- Rust 工作区清单与锁文件（`Cargo.toml`、`Cargo.lock`），以及适配器校验依赖锁文件
  `requirements-jsonschema.lock`
- 运行和验证入口：[入门指南](getting-started.md)、[质量门禁](quality-gates.md)与
  `scripts/check_rust_quality.sh`

上述是仓库内容清单。打包、安装、更新和真实设备验证结果须分别提供证据。
