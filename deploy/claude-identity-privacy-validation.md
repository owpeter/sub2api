# Claude Code 身份隐私模式：验证记录

基于提交 `92c9433d40db69b00f8e158fc573e2b796c4a678` 的本地修改，
在 Windows、Go 1.27.2、pnpm 9 环境验证。部署与功能边界见
[启用说明](claude-identity-privacy.md)。功能尚未在真实上游启用。

## 已通过

- 新增 19 个 Go 顶层测试及其子用例，覆盖入口、两类请求构造器、管理设置、路由、
  错误诊断和真实 HTTP 发送层。发送层连接本地 `httptest` 服务。
- 回放 14 条本机 Claude Code 2.1.300 实际 Messages 请求：6 条兼容样本可以转发，
  8 条含非空 safeguards 的样本按预期拒绝。虚拟凭证与隔离配置用于采样；
  count_tokens 测试输入由这些样本构造。入库样本保留协议结构，长提示词及工具描述使用合成文本。
- 校验设备与会话假名在重试、并发、重启时稳定，在租户、分组、部署及上游账号间隔离；
  会话头与正文一致，agent/parent 关系保持，未知请求头、Host 覆写和 Trailer 不发送。
- 检查 400/401/403/429/500/503 错误，即使启用详细日志也不持久化测试中的敏感回显标记。
- SettingsView 与语言键测试：48 项通过；前端类型检查及修改文件的 ESLint 通过。
- 涉及的后端包 `go vet -tags unit` 通过，`git diff --check` 通过。
- 网关、身份、设置、beta、限流、运维和 IP 的相关回归测试通过。
  路由测试最初的硬编码中间件链断言已更新，并重新通过全部 `TestGatewayRoutes` 测试。

最终隐私与路由检查命令：

```sh
cd backend
go test -mod=readonly -tags unit -p=4 ./internal/service ./internal/handler ./internal/handler/admin ./internal/repository ./internal/server/routes ./internal/config -run '^TestClaudePrivacy|^TestGatewayRoutes' -count=1
go vet -tags unit ./internal/service ./internal/handler ./internal/handler/admin ./internal/server/routes ./internal/repository ./internal/config ./internal/pkg/ip
```

## 更大范围测试的失败

没有将整个仓库标记为全绿。运行 service、handler、admin、config、IP、middleware 包的
完整单元测试时出现以下失败；使用 Go overlay 加载未修改的上述基线提交进行对照，
没有切换或重置工作区。

| 用例 | 本次观察 |
| --- | --- |
| `TestOllamaProbeCallback_StaleLongDoesNotOverrideNewShort` | 当前代码与基线都失败 |
| `TestResolvePageImagePath` | 当前代码与基线都失败，涉及 Windows 路径判断 |
| `TestCommandCodeGatewayPassesThroughCatalogProtocols` | 当前包全量运行失败；当前代码单独重跑、基线单独及包全量运行通过，尚未稳定复现 |
| `TestCanonicalOpenAIAccountSchedulingModelMatchesForwardSemantics` | 当前包全量运行失败；当前代码单独重跑、基线单独及包全量运行通过，尚未稳定复现 |
| `TestInflightEstimate_AccountMappingNoDBAndBoundedMemory` | 基线包全量运行出现额外的内存阈值失败 |

以上未通过项未作为本功能修改范围去修复。相关回归筛选排除了前四个用例；
这些结果不能证明未稳定复现的两个失败一定与本次修改无关。

## 未验证

未发送真实 Anthropic OAuth 请求，未验证官方上游接受情况、真实原生 count_tokens、
子 agent/会话压缩（compaction）流量或 TLS 指纹；并发映射用例已运行，但没有运行 Go race 检测。
隐私模式不处理提示词、代码及工具结果里的本地路径或其他身份文字，也不保证账号不受限制。
