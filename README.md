# 账号密码库（Password vault）

本地加密的账号密码库。**一次配置，之后 AI 直接调用；密码只在本机使用，不以明文进入对话，也不上传到任何第三方服务。**

## 它解决什么问题

以前让 AI 操作某个服务时，每次都要：

1. AI 问你账号密码；
2. 你不想把密码发在对话里；
3. AI 临时弹一个密码输入框；
4. 下个任务再来一遍。

安装这个插件后：

1. 在 **设置 → 账号密码库** 里创建密码库；
2. AI 需要登录时先调用 `vault_list` 找账号；
3. 如果还没有这个账号，AI 调用 `vault_capture`，插件在页面内弹出安全输入框；你只需要输入一次密码，它直接加密入库，**不会进入对话**；
4. AI 拿到条目元数据和租约，用 `vault_exec` 或 `vault_http` 使用凭据；
5. AI 只看到租约和脱敏后的结果，**看不到密码明文**。

也可以随时在设置页手动添加、编辑、删除账号。

## 安全模型

| 项目 | 做法 |
| --- | --- |
| 落盘加密 | 每条记录用 AES-256-GCM 加密，附带完整性校验；文件里没有明文账号、密码、备注或标签 |
| 密钥保护 | 默认用 Windows DPAPI（当前 Windows 账户）保护随机生成的 256 位密钥，DSH 重启后自动解锁；也可以设置主密码，用 scrypt 派生密钥包裹 |
| 自动锁定 | 主密码模式下闲置 30 分钟自动锁定；DPAPI 模式下重启自动解锁 |
| AI 访问 | 每次只发一个条目、10 分钟有效的随机租约；条目可单独关闭 AI 访问 |
| 一次性录入 | `vault_capture` 只在插件 UI 里收集密码，直接写入加密库；AI 只收到条目元数据和租约。允许的主机由用户看到的 URL 决定，AI 不能扩大 |
| 命令使用 | `vault_exec` 默认关闭，需要用户在 **设置 → 账号密码库 → 高级设置** 显式开启；开启后把密码放进子进程环境变量，不放在命令行参数里，输出返回前过滤密码及其 URL 编码、Base64 变体 |
| HTTP 使用 | `vault_http` 只向条目允许的主机发送凭据；不跟随重定向；过滤响应中的密码和 `Set-Cookie` |
| 本地管理 | 设置页通过 `127.0.0.1` 同源接口访问 Host；密码不写入配置文件、不进入会话日志 |
| 审计 | 只记录操作、条目名称、时间和结果，不记录密码 |

密码库默认路径：

```text
%USERPROFILE%\.dsh\password-vault\vault.json
```

同目录还有 `vault.json.bak`（上一版密文备份）和 `audit.jsonl`（无密码审计）。

> 从旧的 `@local/password-vault` 升级到当前的 `dsh-password-vault` 后，客户端插件 ID 会变化。请完全退出并重启一次 DSH，设置页才会加载新的客户端。密码库数据不受影响。

## 安装

在 DSH 中把本目录作为本地插件的安装目标：

```text
E:\AI\DS\password-vault
```

或让 DSH 执行：

```text
plugin_manager install_bundle  target: E:\AI\DS\password-vault
```

安装后打开 **设置（Settings）→ 账号密码库**：

1. 点“创建密码库”；
2. 主密码留空 = 使用 Windows 账户自动解锁（推荐，后续不再提示）；
3. 点“添加账号”，填写名称、账号、密码、网址；
4. 根据需要设置认证方式（Basic / Bearer / 自定义请求头 / 查询参数）、TOTP、允许的主机。

## AI 工具

| 工具 | 用途 |
| --- | --- |
| `vault_status` | 查看是否已创建、是否解锁、可用的条目数 |
| `vault_list` | 列出允许 AI 使用的条目（只有掩码账号、网址、标签等元数据） |
| `vault_capture` | 打开一次性的本机安全输入框；用户输入密码后直接加密入库，AI 只拿到元数据和租约 |
| `vault_use` | 为某个条目申请短期租约，不返回密码 |
| `vault_exec` | 默认关闭；用户在高级设置开启后，执行命令并把凭据放在 `VAULT_*` 环境变量中，输出自动脱敏 |
| `vault_http` | 发起 HTTP 请求，按条目的认证方式注入凭据；只允许条目配置的主机 |

### `vault_exec` 环境变量

```text
VAULT_USERNAME
VAULT_PASSWORD
VAULT_SECRET
VAULT_TOKEN
VAULT_TOTP
VAULT_URL
VAULT_NOTES
VAULT_LABEL
VAULT_AUTH_TYPE
VAULT_AUTH_KEY
```

示例（AI 侧）：

```powershell
# 不要自己拼接密码，直接使用环境变量
curl.exe -u "$env:VAULT_USERNAME`:$env:VAULT_PASSWORD" https://example.com/api
```

### `vault_http` 占位符

在 URL、请求头或请求体里可用：

```text
{{username}}  {{password}}  {{secret}}  {{totp}}  {{auth_key}}  {{label}}  {{url}}
```

例如：

```json
{
  "lease": "...",
  "url": "https://api.example.com/session",
  "method": "POST",
  "headers": { "X-API-Key": "{{password}}" },
  "body": "{\"username\":\"{{username}}\",\"otp\":\"{{totp}}\"}"
}
```

## 重要限制

- **`vault_exec` 默认关闭。** 需要在高级设置里显式开启；开启后，AI 可以用租约执行命令并接触凭据。完成敏感任务后建议关闭。
- **AI 看不到密码，但命令仍可能把环境变量发到别处。** `vault_exec` 会过滤输出里的密码，但无法阻止一个恶意命令主动把 `$env:VAULT_PASSWORD` 发到网络。只让 AI 运行可信命令。
- **HTTP 只发往条目允许的主机。** 默认是条目网址的主机；需要多个主机时在条目里用逗号配置，支持 `*.example.com`。不要配置过宽的 `*`。
- **`vault_capture` 的字段是 Agent 预填的。** 输入密码前核对名称和网址。允许的主机由你看到的 URL 派生，AI 不能在这个流程里扩大主机范围。
- **显示明文只在本地设置页。** “使用详情 → 显示”会把密码渲染在本机页面上；它不会进入会话，但请只复制到真正需要的地方。
- **主机被攻破时无法保护。** 如果攻击者已经能以你的 Windows 账户运行代码，DPAPI 和本插件都无法阻止它读取内存或文件。加密主要防止磁盘、备份、云同步泄露。
- **不要上传 `vault.json`、`vault.json.bak` 到网盘或聊天。** 虽然内容是密文，但没有必要扩大暴露面。
- **备份。** 升级或重置前复制整个 `%USERPROFILE%\.dsh\password-vault` 目录；丢失密钥保护信息后无法恢复密码。

## 卸载

在插件管理页移除 `dsh-password-vault`。密码库文件不会自动删除；需要彻底清除时手动删除 `%USERPROFILE%\.dsh\password-vault`。

## 作者与许可证

- 作者：小马大大哥哥
- 许可证：MIT（允许使用、修改、再分发；保留版权与许可证声明；不提供担保）
- 源码：<https://github.com/qq601359558/dsh-password-vault>
- Release：<https://github.com/qq601359558/dsh-password-vault/releases/tag/v1.1.0>
- DSH 发现索引：<https://raw.githubusercontent.com/qq601359558/dsh-password-vault/main/index.json>
- 上架打包说明见 [PUBLISH.md](PUBLISH.md)

## 开发与测试

```powershell
node --check .\lib\vault.js
node --check .\index.js
node --check .\client.js
node --test .\test\vault.test.mjs
```

测试使用临时目录，不会碰真实密码库；包含密文检查、防篡改、DPAPI、租约、命令注入、HTTP Basic 注入、重定向拒绝、TOTP 和脱敏。
