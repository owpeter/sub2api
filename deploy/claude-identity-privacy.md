# Claude Code 身份隐私模式（v1）

此模式用于原生 Claude Code 通过 sub2api 调用 Anthropic OAuth / Setup Token
账号时，隐藏下游设备、账号、会话标识及请求头中的本地系统和运行时信息。
默认关闭，按入站 Anthropic 分组启用，覆盖 Messages 和 count_tokens（包括根路径计数别名）。
它不保证请求与官方直连不可区分，也不保证账号不会受限制。

## 启用

1. 生成一次独立的 32 字节随机密钥，例如 `openssl rand -base64 32`。
   将结果存入部署的秘密配置，不要放进仓库、普通设置 JSON 或日志。
2. 设置以下环境变量，重启服务。所有副本使用相同密钥和命名空间。
   这两个变量已接入 `docker-compose.yml` 和 `docker-compose.local.yml`。

   ```dotenv
   GATEWAY_CLAUDE_IDENTITY_PRIVACY_KEY=<32 字节随机密钥的标准 Base64 编码>
   GATEWAY_CLAUDE_IDENTITY_PRIVACY_NAMESPACE=<稳定且独立的部署名称>
   ```

   也可以使用 `config.yaml` 的 `gateway.claude_identity_privacy.key` 和
   `gateway.claude_identity_privacy.namespace`。不要复用 JWT、TOTP 或 OAuth 密钥。
3. 在「管理 → 系统设置 → 网关」中的「Claude Code 身份隐私」勾选专用 Anthropic 分组并保存。
   确保该组仅使用 OAuth / Setup Token 账号，且账号的 `extra.account_uuid` 已正确配置。
4. 下游继续使用真实 Claude Code。在本次验证的 2.1.300 中，使用
   `claude --permission-mode manual` 可以保留人工权限确认，并避免发送自动权限判断上下文。
   如果实际请求仍含非空 `safeguards`，网关会拒绝它。

管理 API 的系统设置字段为：

```json
{
  "claude_code_identity_privacy": {
    "version": 1,
    "enabled_group_ids": [7]
  }
}
```

GET 只额外返回 `claude_code_identity_privacy_ready` 表示部署配置是否有效，不返回密钥。
部分更新省略该配置时保持原值；显式保存空分组列表可关闭。管理员可以在密钥失效时取消已有选择。
无效的存储配置显示 `version: 0`，必须显式修复或重置；不会自动降级成关闭。

本实例保存后立即清理策略缓存；其他副本最多约 5 秒刷新。缓存过期后若数据库查询失败，
Messages/计数请求返回固定错误，因为此时无法可靠判定该分组是否需要保护。
部署密钥和命名空间不自动热轮换；更换会改变假名，应在维护窗口结束旧会话后进行。

## 字段处理

| 字段 | 出口行为 |
| --- | --- |
| `metadata.user_id.device_id` | HMAC-SHA256 派生的 64 位十六进制假名 |
| 下游 `account_uuid` | 不转发；使用已选上游账号自身的 UUID |
| metadata/session header | 映射为同一个 UUID 假名；冲突、重复、未知格式报错 |
| agent / parent-agent | 使用同一映射域，保留父子关系 |
| prompt ID | 在会话内稳定映射；缺失时保持缺失 |
| `x-client-request-id` | 原来存在才生成新 UUID，同次网关重试复用；内部追踪 ID 独立生成 |
| User-Agent | 保留经过校验的实际版本和 `cli` / `sdk-cli` 入口，去除任意尾缀 |
| 六个 `x-stainless-*` 系统、架构、语言、SDK、运行时字段 | 省略 |
| Cookie、转发 IP、语言、浏览器环境、未知自定义头及工具耗时 | 不发往上游 |
| retry / timeout | 只保留有效数值 |
| version / beta | 校验协议格式，保留客户端能力；单独补 OAuth 所需 beta。冲突的管理员 beta 过滤规则会报错 |
| system、messages、tools、有效 thinking 签名、工具引用、缓存断点和 billing 归因块 | 不为身份隐私进行改写 |

作用域包含部署命名空间、入站分组 ID、认证后的 API key ID。内部调度键独立于上游账号；
出站设备和会话假名再按选中的上游账号隔离。相同密钥与作用域下，重启、并发和重试保持稳定。
更换上游账号会改变出站假名，不会把已经替换的 ID 再次散列。
UUID 使用 UUIDv5 编码 HMAC 派生值，属于网关假名，不声称复刻客户端的随机 ID 算法。

没有身份字段的 count_tokens 和一 token Haiku 探测请求保持缺失。
隐私请求跳过旧指纹缓存、metadata 透传、会话合并、完整 mimic、账单版本同步、
日期归一化和 1h 缓存注入。既有模型映射、计费、鉴权与协议错误修复仍独立生效。

入口先完成鉴权，再准备隐私状态，随后才进行模型准入、平台分流和调度。
出口重新构造允许的请求头；旧默认头或账号覆写不能重新加入被清理的信息。
入口的可信代理/IP 解析结果保留给鉴权、限流及网关自身记录，不随原转发头送出。

## 兼容性边界与诊断

- `privacy_incompatible_classifier_context`：v1 拒绝所有非空 safeguards，以及不符合数组格式的 safeguards。
  不删除安全字段、不伪造权限判断输入、不自动修改客户端权限模式。
- `privacy_session_mismatch` / `privacy_ambiguous_json` / `privacy_ambiguous_headers`：身份输入不一致或有歧义。
- `privacy_key_not_configured` / `privacy_upstream_account_uuid_missing`：补齐部署配置或所选上游账号信息。
- `privacy_unsupported_group` / `privacy_unsupported_upstream`：当前路由超出首版支持范围。
  已启用分组即使后来更改平台，也不会绕过保护走另一套 Messages 转发器。
- `privacy_incompatible_beta_policy`：管理员 beta 过滤规则与本次请求能力冲突，需要显式调整策略。
- `privacy_settings_unavailable`：无法可靠读取隐私策略，停止发送，恢复设置存储后重试。

错误信息不回显原标识。原始请求快照、上游错误片段、运维错误队列和账号限流错误说明
均有隐私保护；成功请求使用规范化 UA 和内部会话假名。仍保留必要的网关管理 ID、状态码、
路由与 IP 安全记录。鉴权前被拒绝的请求沿用入口日志策略；历史日志、反向代理日志和
第三方部署插件的额外记录不由此功能清除。

提示词、代码、工具结果中的用户名、目录、系统描述仍可能发送给模型。
本功能只覆盖上述身份字段与请求头；不是完整机器匿名化。
TLS 与出口 IP 继续由网关建立连接的方式决定。

## 验证

新增测试覆盖两端点、重试/换账号、跨实例稳定性、作用域隔离、agent 父子关系、prompt 关联、
缺失身份的辅助请求、重复字段、配置读取失败、旧策略覆盖、路由提前拦截、管理端部分更新与修复，
以及开启详细日志后的 400/401/403/429/500/503 诊断脱敏。

测试数据包含本机 Claude Code 2.1.300 在隔离配置和虚拟凭证下发出的 14 条实际 Messages 请求。
其中 6 条为可转发基线，8 条带 safeguards 应被拒绝。计数测试由样本构造，未实测原生 count_tokens。
样本不含真实认证信息，本机路径已替换，长提示词与工具描述已缩减为合成文本；见
[`testdata/claude_identity_privacy`](../backend/internal/service/testdata/claude_identity_privacy/README.md)。

```sh
cd backend
go test -tags unit ./internal/service ./internal/handler ./internal/handler/admin ./internal/server/routes ./internal/repository ./internal/config -run '^TestClaudePrivacy'
cd ../frontend
pnpm typecheck
pnpm exec vitest run src/views/admin/__tests__/SettingsView.spec.ts src/i18n/__tests__/localeKeyCompleteness.spec.ts
```

本地 mock 测试未联系真实 Anthropic 上游；真实 OAuth 接受情况、子 agent/会话压缩实测流量及 TLS
兼容性仍需要在部署环境单独验证。功能保持默认关闭。

已运行的检查及更大范围测试的失败记录见[验证记录](claude-identity-privacy-validation.md)。
