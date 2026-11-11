# 发布到 DSH 插件商城

作者：小马大大哥哥  
许可证：MIT  
源码：<https://github.com/qq601359558/dsh-password-vault>  
Release：<https://github.com/qq601359558/dsh-password-vault/releases>

## 1. 发布前自检

```powershell
npm run check:store
```

检查包名、版本、`plugin.json`、`dsh.plugin.json`、`engines.dsh`、图标、双语元数据和必需文件。

## 2. 生成 zip（deepseek.stream 社区商城）

```powershell
npm run pack:store
```

输出：

```text
dist/dsh-password-vault-<version>.zip
```

zip 内是一个顶层 `dsh-password-vault/` 目录，包含：

```text
package.json
plugin.json
dsh.plugin.json
cordis.patch.yml
index.js
client.js
lib/vault.js
locale/en.json
locale/zh.json
icon.svg
README.md
LICENSE
```

然后登录 <https://deepseek.stream/upload>，选择「扩展插件」，上传这个 zip。商店会解析 Bundle 规范和插件元数据。

## 3. 发布到 npm（官方 Discover / 索引使用）

```powershell
npm publish --registry=https://registry.npmjs.org
```

发布后，包名是 `dsh-password-vault`。用户也可以用：

```powershell
dsh plugin --profile <name> add dsh-password-vault
```

## 4. 发布到官方 Discover 索引

仓库根目录已经带了 `index.json`。DSH 的 **插件 → 发现 → 添加索引源** 可以填：

```text
https://raw.githubusercontent.com/qq601359558/dsh-password-vault/main/index.json
```

如果 raw.githubusercontent.com 访问不稳定，可以把 `index.json` 和 `icon.svg` 放到 GitHub Pages / 任意 HTTPS 静态站点，使用自己的 URL。

索引内容示例：

```json
{
  "format": 1,
  "title": { "en": "小马大大的插件", "zh": "小马大大的插件" },
  "plugins": [
    {
      "name": "dsh-password-vault",
      "title": { "en": "Password vault", "zh": "账号密码库" },
      "description": {
        "en": "Encrypted local accounts that the agent can use without seeing passwords.",
        "zh": "本地加密保存账号密码，AI 可通过租约直接使用，但看不到明文。"
      },
      "icon": "icons/dsh-password-vault.svg",
      "author": "小马大大哥哥",
      "versions": [
        {
          "version": "1.1.0",
          "publishTimestamp": 0,
          "source": { "type": "npm" },
          "engines": { "dsh": ">=0.2.2-rc.1 <0.3.0" }
        }
      ]
    }
  ]
}
```

把 `index.json` 和 `icons/dsh-password-vault.svg` 放到任意 HTTPS 静态站点，用户在 **插件 → 发现 → 添加索引源** 中填入 `index.json` 的 URL 即可。`publishTimestamp` 需要替换为实际的 Unix 秒级发布时间。

## 5. 重要提醒

- 当前构建使用 Windows DPAPI 自动解锁，`plugin.json` 标记为 `platform: desktop-exe`。macOS/Linux 需要主密码模式，发布前应先补平台适配或明确标注仅 Windows。
- `vault_exec` 默认关闭；用户必须在 **设置 → 账号密码库 → 高级设置** 显式开启。商城权限说明已按此填写。
- 密码管理器属于高敏感插件。建议同时提供公开源码仓库、安全说明和隐私政策，并在发布前用干净的 DSH profile 做一次安装验证。
- 不要上传本机的 `%USERPROFILE%\.dsh\password-vault` 数据目录；它包含真实凭据的密文和密钥保护信息。
