# MCP CapaGate

面向 MCP 工具调用的能力图谱、安全策略编译器与运行时防火墙。

[English README](README.md)

![MCP CapaGate preview](docs/assets/capagate-preview.svg)

MCP CapaGate 会把 MCP 工具定义转换成能力图谱，编译最小权限策略，并在工具真正执行之前通过透明代理拦截高风险调用。

它不是普通 scanner，也不是新的聊天机器人框架。它的核心是：用确定性的方式理解工具能力、工具组合风险、策略决策和运行时审计。

## MCP 工具调用的风险

MCP 工具让 Agent 能够读文件、查数据库、发邮件、退款、调用 webhook，甚至执行 shell 命令。问题不只是“工具描述里有没有可疑词”，而是：

- 这个工具实际具备什么能力？
- 它能不能读取隐私数据？
- 它能不能把数据发到外部系统？
- 它和其他工具组合后会不会形成攻击链？
- 工具 schema 更新后，风险有没有漂移？

MCP CapaGate 用能力图谱回答这些问题。

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

`v0.1.0` release tag 创建之后，外部用户可以这样使用发布后的 Action：

```yaml
- uses: choose-hy/mcp-capagate@v0.1.0
  with:
    config: capagate.yaml
    fail-on: high
    report-dir: reports
```

在本仓库内做本地开发或 smoke test 时，可以使用 `uses: ./`。

Action 会安装依赖、构建项目、扫描 MCP 工具、生成 policy、生成 Markdown/HTML/SARIF 报告，并把 Markdown 报告写入 GitHub Step Summary。

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
