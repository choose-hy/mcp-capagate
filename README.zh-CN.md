# MCP CapaGate

面向 MCP 工具调用的能力图谱、安全策略编译器与运行时防火墙。

[English README](README.md)

![MCP CapaGate preview](docs/assets/capagate-preview.svg)

在工具真正执行前阻断高风险 MCP 调用。

MCP CapaGate 会把 MCP 工具 schema 转换成能力图谱，编译最小权限策略，并通过确定性的运行时代理执行 `ALLOW` / `WARN` / `REQUIRE_APPROVAL` / `BLOCK` 决策。

```text
read_order: ALLOW
issue_refund: REQUIRE_APPROVAL or BLOCK
execute_shell: BLOCK
read_secret + send_email: BLOCK
```

`Tool Schema -> Capability Extraction -> Capability Graph -> Policy Compiler -> Runtime Firewall -> Audit Receipts + Reports`

它不是普通 scanner，也不是新的聊天机器人框架。它可以完全本地运行，不需要训练数据、微调、专有数据、数据库、遥测或 LLM API key。

## MCP 工具调用的风险

MCP 工具让 Agent 能够读文件、查数据库、发邮件、退款、调用 webhook，甚至执行 shell 命令。一旦 LLM 可以调用工具，prompt injection 就不再只是文本风险，而可能变成执行风险。

问题不只是“工具描述里有没有可疑词”，而是：

- 这个工具实际具备什么能力？
- 它能不能读取隐私数据？
- 它能不能把数据发到外部系统？
- 它和其他工具组合后会不会形成攻击链？
- 工具 schema 更新后，风险有没有漂移？

看起来安全的工具也可能组合成危险路径：先读取客户资料，再发送邮件；先写文件，再执行 shell；先添加转发规则，再持续外发数据。

## CapaGate 做什么

`Tool Schema -> Capability Extraction -> Capability Graph -> Policy Compiler -> Runtime Firewall -> Audit Receipts + Reports`

MCP CapaGate 用能力图谱回答这些问题：把每个工具映射成能力节点，合成最小权限策略，在运行时防火墙里阻断高风险调用，并为每次决策生成审计 receipt。

没有 CapaGate：

- 工具风险是隐含的
- schema 漂移可能不被发现
- 安全工具可能串成外泄链路
- 高风险调用可能先执行、后审查

有 CapaGate：

- 工具变成明确的能力节点
- 高风险能力有显式 policy
- 危险调用在执行前被阻断
- 每次决策都有审计 receipt

## 为什么需要能力图谱

能力图谱把每个工具映射成 `CapabilityNode`，包含：

- 工具名和 server
- 能力标签，例如 `read_data`、`send_message`、`shell_execution`
- 风险等级：`low`、`medium`、`high`、`critical`
- 数据敏感度：`public`、`internal`、`private`、`secret`
- 影响半径
- 所需控制措施
- 证据和置信度

图谱边会表达工具组合风险，例如：

- 先读取隐私数据，再发送邮件
- 先写文件，再执行 shell
- 跨 server 同名工具造成 shadowing
- 能访问私密数据
- 能修改状态

## 为什么不是普通 Scanner

普通 scanner 通常输出“发现了可疑字符串”。MCP CapaGate 进一步做三件事：

1. 把 tool schema 编译成能力图谱。
2. 根据能力图谱合成最小权限 policy。
3. 在运行时代理中执行 `ALLOW`、`WARN`、`REQUIRE_APPROVAL`、`BLOCK` 决策。

整个 MVP 不需要训练数据、不需要微调、不需要专有数据、不需要数据库、不需要遥测，也不需要 LLM API key。

## 本地运行

```bash
pnpm install
pnpm build
pnpm --filter @mcp-capagate/cli capagate demo
```

Demo 会生成：

- `reports/scan.json`
- `capagate.policy.yaml`
- `reports/summary.md`
- `reports/index.html`
- `.capagate/audit.jsonl`

## CLI 示例

```bash
capagate scan --input examples/refund-server/tools.json --out reports/scan.json
capagate policy --input reports/scan.json --out capagate.policy.yaml
capagate report --scan reports/scan.json --policy capagate.policy.yaml --html reports/index.html --markdown reports/summary.md
capagate wrap --policy capagate.policy.yaml -- npx your-mcp-server
```

运行时代理会透明转发非 `tools/call` 的 JSON-RPC 消息。遇到 `tools/call` 时，它会解析工具名和参数、评估 policy、检查会话级攻击链、写入审计 receipt，并在失败时默认关闭。

## GitHub Action

外部用户应该使用发布后的 Action，例如 `choose-hy/mcp-capagate@v0.1.0`：

```yaml
name: MCP CapaGate

on:
  pull_request:
  workflow_dispatch:

jobs:
  mcp-capagate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: choose-hy/mcp-capagate@v0.1.0
        with:
          config: capagate.yaml
          fail-on: high
          report-dir: reports
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mcp-capagate-report
          path: reports/
```

- `fail-on: high` 表示发现 high 或 critical 风险时让 workflow 失败。
- `report-dir` 表示报告输出目录，会包含 scan JSON、Markdown、HTML 和 SARIF 报告。
- Markdown 报告也会写入 GitHub Step Summary。
- 在本仓库内做本地开发或 smoke test 时，可以使用 `uses: ./`。

## 更多文档

- [Limitations](docs/limitations.md)：部署边界、安全假设和 MVP 已知限制。
- [Comparison](docs/comparison.md)：CapaGate 与 scanner、通用 guardrail、observability 和 OS sandbox 的区别。
- [Policy DSL](docs/policy-dsl.md)：用于路径、域名、金额、确认标记和参数模式的工具调用约束。
- [Runtime Modes](docs/runtime-modes.md)：运行时代理的 enforce、shadow 和 audit-only 模式。
- [Taint Tracking](docs/taint-tracking.md)：会话 taint 标签和外部 sink 攻击链检测。

## 如何在面试或项目介绍里讲

可以这样介绍：

> 我做了一个 MCP 工具调用安全项目。它不是简单扫描工具描述，而是把 MCP tool schema 映射成 capability graph，再根据图谱合成 least-privilege policy，并通过本地 JSON-RPC 代理在工具执行前做确定性拦截。

更技术化一点：

> We propose a capability-aware policy compiler for MCP tools that maps tool schemas to a risk graph, synthesizes least-privilege policies, and enforces them at runtime through a deterministic MCP proxy.

这个项目的亮点是：

- 有清晰 threat model
- 有 deterministic capability extraction
- 有 policy compiler
- 有 runtime firewall
- 有 drift detection
- 有 attack-chain detection
- 有 audit receipt
- 有 GitHub Action
- 可以完全本地运行

## 安全说明

MCP CapaGate 是 guardrail，不是 OS sandbox。生产使用时仍然应该让上游 MCP server 以最小权限运行。示例和测试只包含安全的合成数据，不应放入真实密钥。

## License

MIT
