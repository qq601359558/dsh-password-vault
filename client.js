window.__ModuleLoader__.load({
  id: 'dsh-password-vault',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useCallback, useEffect, useMemo, useRef, useState } = React;

    const NS = 'password-vault';

    const en = {
      nav: 'Password vault',
      title: 'Password vault',
      subtitle: 'Encrypted local accounts that the agent can use without seeing passwords.',
      loading: 'Loading…',
      refresh: 'Refresh',
      lock: 'Lock',
      unlock: 'Unlock',
      statusUnconfigured: 'Not created',
      statusLocked: 'Locked',
      statusUnlocked: 'Unlocked',
      statusBroken: 'Unreadable',
      protectionDpapi: 'Windows account (DPAPI)',
      protectionPassword: 'Master password',
      protectionNone: 'No protection',
      setupTitle: 'Create your vault',
      setupIntro: 'Create the encrypted vault once, then add the accounts you want the agent to use. Passwords are encrypted with AES-256-GCM and never enter the chat.',
      setupPassword: 'Master password (optional)',
      setupPasswordHint: 'Leave both password fields empty to unlock automatically with your Windows account. Set a password if you want the vault to lock when DSH restarts.',
      setupConfirm: 'Confirm master password',
      createVault: 'Create vault',
      creating: 'Creating…',
      passwordMismatch: 'The two passwords do not match.',
      unlockTitle: 'Unlock the vault',
      unlockIntro: 'The vault is locked. Unlock it here once; the agent tools resume immediately.',
      masterPassword: 'Master password',
      unlockAction: 'Unlock',
      unlocking: 'Unlocking…',
      autoUnlockAction: 'Unlock with Windows account',
      brokenTitle: 'The vault file cannot be read',
      brokenIntro: 'The encrypted file exists, but it is corrupted or was changed. Do not create a new vault over it.',
      brokenHint: 'Restore vault.json.bak or a backup, or move the damaged file aside and create a new vault.',
      addEntry: 'Add account',
      addFirst: 'Add your first account',
      search: 'Search accounts',
      noEntries: 'No accounts yet. Add the first one here; the agent can then list and use it without asking for the password.',
      noMatches: 'No accounts match this search.',
      account: 'Account',
      password: 'Password',
      totp: 'One-time code',
      url: 'URL',
      authType: 'Authentication',
      authKey: 'Header or query name',
      tags: 'Tags',
      notes: 'Notes',
      allowedHosts: 'Allowed hosts',
      allowInsecure: 'Allow plain HTTP (not recommended)',
      aiAccess: 'AI access',
      aiOn: 'AI can use',
      aiOff: 'AI blocked',
      show: 'Use details',
      hide: 'Hide details',
      showSecret: 'Show',
      hideSecret: 'Hide',
      copy: 'Copy',
      copied: 'Copied.',
      copyFailed: 'Could not copy to the clipboard.',
      edit: 'Edit',
      delete: 'Delete',
      cancel: 'Cancel',
      save: 'Save',
      saving: 'Saving…',
      deleteConfirm: 'Delete this account?',
      deleteHint: 'The encrypted record and its outstanding leases will be removed. This cannot be undone.',
      editorNew: 'Add account',
      editorEdit: 'Edit account',
      fieldLabel: 'Name',
      fieldLabelRequired: 'Enter a name for this account.',
      fieldUsername: 'Account or username',
      fieldPassword: 'Password or token',
      fieldPasswordKeep: 'Leave blank to keep the current password.',
      fieldUrl: 'Sign-in URL',
      fieldAuthType: 'How the secret is attached',
      fieldAuthKey: 'Header or query parameter name',
      fieldTags: 'Tags, separated by commas',
      fieldNotes: 'Notes (stored encrypted)',
      fieldTotp: 'TOTP secret',
      fieldTotpHint: 'Base32 secret or otpauth:// URI. The agent receives codes only inside commands or HTTP requests.',
      fieldAllowedHosts: 'Allowed hosts',
      fieldAllowedHostsHint: 'Comma-separated. Defaults to the URL host. Wildcards like *.example.com are allowed. vault_http refuses every other host.',
      fieldAllowInsecure: 'Allow plain HTTP to non-loopback hosts',
      fieldAi: 'Allow AI tools to use this account',
      clearPassword: 'Clear the stored password',
      clearTotp: 'Clear the stored TOTP secret',
      authNone: 'None (use placeholders manually)',
      authBasic: 'Basic auth',
      authBearer: 'Bearer token',
      authHeader: 'Custom header',
      authQuery: 'Query parameter',
      audit: 'Recent activity',
      auditEmpty: 'No activity recorded yet.',
      auditAction: 'Action',
      auditTime: 'Time',
      auditEntry: 'Account',
      fileLocation: 'Encrypted file',
      privacyTitle: 'How the agent uses it',
      privacyNote: 'The agent gets a short-lived lease, not the password. vault_exec injects the secret into a child process environment; vault_http attaches it only to the hosts you allow. Tool output is scrubbed before it reaches the model.',
      securityNote: 'This page talks to the local DSH Host over loopback. Passwords are never placed in chat messages or plugin configuration.',
      revealHint: 'Plaintext is shown only in this local settings page. Copy it only into the app that needs it.',
      totpRemaining: 'seconds left',
      noUsername: 'No account set',
      noUrl: 'No URL set',
      updated: 'Updated',
      lockedHint: 'The vault is locked, so agent tools cannot use it.',
      notConfiguredHint: 'No vault is configured yet. The agent cannot use saved accounts until you create one.',
      requestFailed: 'The request failed.',
      close: 'Close',
      refreshTotp: 'Refresh code',
      saveFailed: 'The vault did not accept these values.',
      advanced: 'Advanced',
      allowExec: 'Allow vault_exec to run commands',
      allowExecHint: 'Off by default. When on, the agent can run PowerShell/bash commands with a leased credential in environment variables. Only enable this for tasks you trust.',
      allowExecOn: 'vault_exec is enabled. The agent can run commands with leased credentials until you turn it off.',
      allowExecOff: 'vault_exec is off. The agent cannot run commands with credentials.',
      captureTitle: 'Save a credential',
      captureIntro: 'Enter the password once. It is encrypted on this machine and never sent to the model.',
      captureVerify: 'The agent prefilled these fields. Check the name and URL before entering the password.',
      capturePurpose: 'Requested for',
      captureName: 'Name',
      captureUsername: 'Account or username',
      capturePassword: 'Password or token',
      captureUrl: 'URL',
      captureAuthType: 'Authentication',
      captureAuthKey: 'Header or query name',
      captureTotp: 'TOTP secret (optional)',
      captureNotes: 'Notes',
      captureAi: 'Allow AI tools to use this account',
      captureSave: 'Save and continue',
      captureSaving: 'Saving…',
      captureCancel: 'Cancel',
      captureRequired: 'Enter a name and a password or token.',
      captureFailed: 'Could not save this credential.',
      captureClose: 'Close',
      captureShow: 'Show',
      captureHide: 'Hide',
      captureSecure: 'The password is written directly to the encrypted vault over loopback. It is not placed in the chat.',
      captureAiOff: 'AI access is off; the agent will not be able to use this entry.',
      captureExpires: 'This prompt expires in a few minutes.',
    };

    const zh = {
      nav: '账号密码库',
      title: '账号密码库',
      subtitle: '本地加密保存账号密码，AI 可直接使用，但看不到明文。',
      loading: '加载中…',
      refresh: '刷新',
      lock: '锁定',
      unlock: '解锁',
      statusUnconfigured: '未创建',
      statusLocked: '已锁定',
      statusUnlocked: '已解锁',
      statusBroken: '文件损坏',
      protectionDpapi: 'Windows 账户保护（DPAPI）',
      protectionPassword: '主密码保护',
      protectionNone: '未设置保护',
      setupTitle: '创建密码库',
      setupIntro: '只需创建一次，然后把希望 AI 使用的账号添加进来。密码使用 AES-256-GCM 加密，永远不会进入对话。',
      setupPassword: '主密码（可选）',
      setupPasswordHint: '两个密码框都留空时，使用 Windows 账户自动解锁，DSH 重启后也不需要再输入。如果希望重启后需要输入主密码，请在这里设置。',
      setupConfirm: '确认主密码',
      createVault: '创建密码库',
      creating: '创建中…',
      passwordMismatch: '两次输入的主密码不一致。',
      unlockTitle: '解锁密码库',
      unlockIntro: '密码库已锁定。在这里解锁一次，AI 工具会立即恢复可用。',
      masterPassword: '主密码',
      unlockAction: '解锁',
      unlocking: '解锁中…',
      autoUnlockAction: '使用 Windows 账户解锁',
      brokenTitle: '密码库文件无法读取',
      brokenIntro: '加密文件存在，但内容损坏或被修改过。请不要直接覆盖它创建新库。',
      brokenHint: '可以恢复 vault.json.bak 或之前的备份；也可以先把损坏的文件移走，再创建新库。',
      addEntry: '添加账号',
      addFirst: '添加第一个账号',
      search: '搜索账号',
      noEntries: '还没有账号。先在这里添加，之后 AI 就能直接列出并使用，不会再向你要密码。',
      noMatches: '没有匹配的账号。',
      account: '账号',
      password: '密码',
      totp: '动态验证码',
      url: '网址',
      authType: '认证方式',
      authKey: '请求头或查询参数名',
      tags: '标签',
      notes: '备注',
      allowedHosts: '允许的主机',
      allowInsecure: '允许明文 HTTP（不推荐）',
      aiAccess: 'AI 访问',
      aiOn: 'AI 可用',
      aiOff: 'AI 已禁用',
      show: '使用详情',
      hide: '收起详情',
      showSecret: '显示',
      hideSecret: '隐藏',
      copy: '复制',
      copied: '已复制。',
      copyFailed: '复制到剪贴板失败。',
      edit: '编辑',
      delete: '删除',
      cancel: '取消',
      save: '保存',
      saving: '保存中…',
      deleteConfirm: '删除这个账号？',
      deleteHint: '加密记录和尚未过期的租约都会被移除，无法撤销。',
      editorNew: '添加账号',
      editorEdit: '编辑账号',
      fieldLabel: '名称',
      fieldLabelRequired: '请填写这个账号的名称。',
      fieldUsername: '账号或用户名',
      fieldPassword: '密码或令牌',
      fieldPasswordKeep: '留空表示保留当前密码。',
      fieldUrl: '登录网址',
      fieldAuthType: '密码附加方式',
      fieldAuthKey: '请求头或查询参数名',
      fieldTags: '标签，用逗号分隔',
      fieldNotes: '备注（加密保存）',
      fieldTotp: 'TOTP 密钥',
      fieldTotpHint: 'Base32 密钥或 otpauth:// 链接。AI 只能在命令或 HTTP 请求内部拿到动态码。',
      fieldAllowedHosts: '允许的主机',
      fieldAllowedHostsHint: '用逗号分隔；留空时使用网址主机名。支持 *.example.com。vault_http 会拒绝其他主机。',
      fieldAllowInsecure: '允许向非本机地址发送明文 HTTP',
      fieldAi: '允许 AI 工具使用这个账号',
      clearPassword: '清除已保存的密码',
      clearTotp: '清除已保存的 TOTP 密钥',
      authNone: '无（手动使用占位符）',
      authBasic: 'Basic 认证',
      authBearer: 'Bearer 令牌',
      authHeader: '自定义请求头',
      authQuery: '查询参数',
      audit: '最近活动',
      auditEmpty: '还没有活动记录。',
      auditAction: '操作',
      auditTime: '时间',
      auditEntry: '账号',
      fileLocation: '加密文件',
      privacyTitle: 'AI 如何使用',
      privacyNote: 'AI 得到的是短期租约，不是密码。vault_exec 把密码注入子进程环境变量；vault_http 只把密码发送给你允许的主机。工具返回前会自动过滤密码。',
      securityNote: '此页面通过本机回环地址与 DSH Host 通信。密码不会写入对话消息或插件配置。',
      revealHint: '明文只在这个本地设置页显示。请只复制到真正需要它的应用中。',
      totpRemaining: '秒后刷新',
      noUsername: '未设置账号',
      noUrl: '未设置网址',
      updated: '更新于',
      lockedHint: '密码库已锁定，AI 工具暂时无法使用。',
      notConfiguredHint: '还没有创建密码库。创建之后，AI 才能使用保存的账号。',
      requestFailed: '请求失败。',
      close: '关闭',
      refreshTotp: '刷新验证码',
      saveFailed: '密码库没有接受这些内容。',
      advanced: '高级设置',
      allowExec: '允许 vault_exec 执行命令',
      allowExecHint: '默认关闭。开启后，AI 可以在你授予租约后运行 PowerShell/bash 命令，并把凭据放入环境变量。只在你信任当前任务时开启。',
      allowExecOn: 'vault_exec 已开启。在你关闭之前，AI 可以用租约执行命令并接触凭据。',
      allowExecOff: 'vault_exec 已关闭。AI 不能用凭据执行命令。',
      captureTitle: '保存账号凭据',
      captureIntro: '只需在这里输入一次密码。密码会加密保存在本机，不会发送给模型。',
      captureVerify: '这些字段由 Agent 预填。输入密码前请核对名称和网址。',
      capturePurpose: '任务用途',
      captureName: '名称',
      captureUsername: '账号或用户名',
      capturePassword: '密码或令牌',
      captureUrl: '网址',
      captureAuthType: '认证方式',
      captureAuthKey: '请求头或查询参数名',
      captureTotp: 'TOTP 密钥（可选）',
      captureNotes: '备注',
      captureAi: '允许 AI 工具使用这个账号',
      captureSave: '保存并继续',
      captureSaving: '保存中…',
      captureCancel: '取消',
      captureRequired: '请填写名称和密码/令牌。',
      captureFailed: '保存失败。',
      captureClose: '关闭',
      captureShow: '显示',
      captureHide: '隐藏',
      captureSecure: '密码通过本机回环接口直接写入加密库，不会进入对话。',
      captureAiOff: '已关闭 AI 访问，Agent 将无法使用这个条目。',
      captureExpires: '这个输入窗口会在几分钟后失效。',
    };

    const css = `
.pv-root{display:flex;flex-direction:column;gap:14px;padding-bottom:28px;color:var(--dsw-alias-label-primary);font-size:13px;line-height:1.5}
.pv-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.pv-heading{display:flex;align-items:center;gap:10px;min-width:0}
.pv-mark{width:34px;height:34px;border-radius:10px;background:var(--dsw-alias-bg-module-platform);display:flex;align-items:center;justify-content:center;flex:none;color:var(--dsw-alias-brand-primary)}
.pv-title{margin:0;font-size:18px;font-weight:600;line-height:1.35}
.pv-subtitle{margin:3px 0 0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:1.5}
.pv-head-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.pv-pill{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;padding:3px 9px;font-size:11px;line-height:1.5;color:var(--dsw-alias-label-secondary);white-space:nowrap}
.pv-pill:before{content:"";width:6px;height:6px;border-radius:50%;background:var(--dsw-alias-state-idle-primary)}
.pv-pill.ok:before{background:var(--dsw-alias-state-success-primary)}
.pv-pill.warn:before{background:var(--dsw-alias-state-warn-primary)}
.pv-pill.err:before{background:var(--dsw-alias-state-error-primary)}
.pv-card{border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-2);padding:16px}
.pv-card-tight{padding:12px 16px}
.pv-card h3{margin:0 0 4px;font-size:14px;font-weight:600}
.pv-card p{margin:0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:1.6}
.pv-banner{border:1px solid var(--dsw-alias-border-l2);border-radius:10px;padding:9px 12px;font-size:12px;line-height:1.55}
.pv-banner.err{color:var(--dsw-alias-state-error-primary);border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary) 35%,var(--dsw-alias-border-l2))}
.pv-banner.ok{color:var(--dsw-alias-state-success-primary);border-color:color-mix(in srgb,var(--dsw-alias-state-success-primary) 35%,var(--dsw-alias-border-l2))}
.pv-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.pv-btn{appearance:none;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);border-radius:8px;padding:5px 11px;font:inherit;font-size:12px;line-height:1.6;cursor:pointer;white-space:nowrap}
.pv-btn:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}
.pv-btn:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:2px}
.pv-btn:disabled{opacity:.55;cursor:default}
.pv-btn.primary{background:var(--dsw-alias-brand-primary);border-color:var(--dsw-alias-brand-primary);color:#fff}
.pv-btn.primary:hover:not(:disabled){filter:brightness(1.06)}
.pv-btn.danger{color:var(--dsw-alias-state-error-primary);border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary) 35%,var(--dsw-alias-border-l2))}
.pv-btn.ghost{border-color:transparent;background:transparent;color:var(--dsw-alias-label-secondary)}
.pv-btn.ghost:hover:not(:disabled){color:var(--dsw-alias-label-primary)}
.pv-btn.small{padding:3px 8px;font-size:11px}
.pv-form{display:grid;gap:10px;margin-top:12px}
.pv-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px}
.pv-field{display:flex;flex-direction:column;gap:4px;min-width:0}
.pv-label{font-size:12px;color:var(--dsw-alias-label-secondary)}
.pv-hint{font-size:11px;color:var(--dsw-alias-label-tertiary);line-height:1.5}
.pv-input,.pv-select,.pv-textarea{width:100%;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);padding:6px 9px;font:inherit;font-size:12px;line-height:1.6}
.pv-textarea{min-height:64px;resize:vertical}
.pv-input:focus,.pv-select:focus,.pv-textarea:focus{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:-1px;border-color:transparent}
.pv-check{display:flex;align-items:flex-start;gap:8px;font-size:12px;color:var(--dsw-alias-label-secondary);line-height:1.5}
.pv-check input{margin:2px 0 0;accent-color:var(--dsw-alias-brand-primary)}
.pv-toolbar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.pv-search{position:relative;flex:1 1 220px;min-width:160px;max-width:340px}
.pv-search .pv-input{padding-left:30px}
.pv-search svg{position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--dsw-alias-label-tertiary);pointer-events:none}
.pv-list{display:flex;flex-direction:column}
.pv-entry{border-top:1px solid var(--dsw-alias-border-l2);padding:12px 0}
.pv-entry:first-child{border-top:none;padding-top:2px}
.pv-entry:last-child{padding-bottom:0}
.pv-entry-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.pv-entry-main{min-width:0;flex:1}
.pv-entry-title{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.pv-name{font-weight:600;font-size:13px;overflow-wrap:anywhere}
.pv-tag{font-size:10px;line-height:1.5;padding:1px 6px;border-radius:999px;background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-tertiary)}
.pv-off{font-size:10px;line-height:1.5;padding:1px 6px;border-radius:999px;color:var(--dsw-alias-state-warn-primary);border:1px solid color-mix(in srgb,var(--dsw-alias-state-warn-primary) 35%,transparent)}
.pv-meta{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-top:3px;color:var(--dsw-alias-label-tertiary);font-size:12px;overflow-wrap:anywhere}
.pv-meta .pv-sep{opacity:.55}
.pv-entry-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end;flex:none}
.pv-switch{position:relative;display:inline-flex;width:32px;height:18px;flex:none;vertical-align:middle}
.pv-switch input{position:absolute;opacity:0;width:100%;height:100%;margin:0;cursor:pointer}
.pv-switch span{position:absolute;inset:0;border-radius:999px;background:var(--dsw-alias-border-l4);transition:background .15s;pointer-events:none}
.pv-switch span:after{content:"";position:absolute;width:14px;height:14px;left:2px;top:2px;border-radius:50%;background:#fff;transition:transform .15s}
.pv-switch input:checked+span{background:var(--dsw-alias-brand-primary)}
.pv-switch input:checked+span:after{transform:translateX(14px)}
.pv-switch input:focus-visible+span{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:2px}
.pv-reveal{margin-top:10px;border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:var(--dsw-alias-bg-layer-1);padding:12px}
.pv-reveal-grid{display:grid;gap:8px}
.pv-reveal-row{display:grid;grid-template-columns:86px minmax(0,1fr);gap:8px;align-items:center}
.pv-reveal-row>span:first-child{color:var(--dsw-alias-label-tertiary);font-size:11px}
.pv-secret{display:flex;align-items:center;gap:6px;min-width:0;flex-wrap:wrap}
.pv-code{font-family:var(--ds-font-family-code,monospace);font-size:12px;background:var(--dsw-alias-bg-module-platform);border-radius:6px;padding:2px 7px;overflow-wrap:anywhere;word-break:break-all}
.pv-reveal-note{margin:8px 0 0;color:var(--dsw-alias-label-tertiary);font-size:11px;line-height:1.55}
.pv-delete{margin-top:10px;border:1px solid color-mix(in srgb,var(--dsw-alias-state-error-primary) 35%,var(--dsw-alias-border-l2));border-radius:10px;padding:10px 12px;background:var(--dsw-alias-bg-layer-1)}
.pv-delete p{margin:0 0 8px;color:var(--dsw-alias-label-secondary);font-size:12px}
.pv-editor{margin-bottom:4px}
.pv-editor-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:2px}
.pv-empty{padding:22px 12px;text-align:center;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:1.6}
.pv-privacy{display:flex;flex-direction:column;gap:4px;color:var(--dsw-alias-label-tertiary);font-size:11px;line-height:1.6}
.pv-privacy strong{color:var(--dsw-alias-label-secondary);font-weight:600}
.pv-path{font-family:var(--ds-font-family-code,monospace);font-size:11px;overflow-wrap:anywhere;word-break:break-all;color:var(--dsw-alias-label-secondary)}
.pv-audit{border-top:1px solid var(--dsw-alias-border-l2);padding-top:10px}
.pv-audit summary{cursor:pointer;color:var(--dsw-alias-label-secondary);font-size:12px;user-select:none}
.pv-audit-list{display:flex;flex-direction:column;gap:0;margin-top:8px}
.pv-audit-row{display:grid;grid-template-columns:120px 1fr 1fr;gap:8px;padding:5px 0;border-top:1px solid var(--dsw-alias-border-l2);font-size:11px;color:var(--dsw-alias-label-tertiary)}
.pv-audit-row:first-child{border-top:none}
.pv-audit-row code{font-family:var(--ds-font-family-code,monospace);color:var(--dsw-alias-label-secondary);overflow-wrap:anywhere}
.pv-audit-empty{color:var(--dsw-alias-label-tertiary);font-size:11px;margin-top:8px}
.pv-muted{color:var(--dsw-alias-label-tertiary)}
.pv-error-text{color:var(--dsw-alias-state-error-primary);font-size:12px;margin-top:8px}
.pv-inline{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
@media (max-width:640px){
.pv-grid{grid-template-columns:1fr}
.pv-head{flex-direction:column}
.pv-head-actions{width:100%;justify-content:flex-start}
.pv-entry-head{flex-direction:column}
.pv-entry-actions{justify-content:flex-start}
.pv-reveal-row{grid-template-columns:1fr}
.pv-audit-row{grid-template-columns:1fr}
}
`;

    const captureCss = `
.pv-capture-backdrop{position:fixed;inset:0;z-index:10000;background:#00000073;display:flex;align-items:center;justify-content:center;padding:24px}
.pv-capture{width:min(580px,100%);max-height:90vh;overflow:auto;box-sizing:border-box;background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l2);border-radius:14px;padding:18px;box-shadow:var(--dsw-elevation-prominent,0 16px 48px #00000033);color:var(--dsw-alias-label-primary);font-size:13px;line-height:1.5}
.pv-capture-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:4px}
.pv-capture-heading{display:flex;align-items:center;gap:10px;min-width:0}
.pv-capture-mark{width:34px;height:34px;border-radius:10px;background:var(--dsw-alias-bg-module-platform);display:flex;align-items:center;justify-content:center;flex:none;color:var(--dsw-alias-brand-primary)}
.pv-capture-title{margin:0;font-size:16px;font-weight:600;line-height:1.4}
.pv-capture-intro{margin:3px 0 0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:1.55}
.pv-capture-close{appearance:none;border:1px solid transparent;background:transparent;color:var(--dsw-alias-label-tertiary);border-radius:7px;width:28px;height:28px;font-size:18px;line-height:1;cursor:pointer;flex:none}
.pv-capture-close:hover{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}
.pv-capture-warning{margin:10px 0 0;color:var(--dsw-alias-state-warn-primary);font-size:11px;line-height:1.55}
.pv-capture-purpose{margin:10px 0 0;padding:7px 10px;border-radius:8px;background:var(--dsw-alias-bg-module-platform);color:var(--dsw-alias-label-secondary);font-size:11px;line-height:1.55;overflow-wrap:anywhere}
.pv-capture-purpose strong{font-weight:600;color:var(--dsw-alias-label-primary)}
.pv-capture-error{margin-top:10px;padding:7px 10px;border-radius:8px;border:1px solid color-mix(in srgb,var(--dsw-alias-state-error-primary) 35%,var(--dsw-alias-border-l2));color:var(--dsw-alias-state-error-primary);font-size:12px;line-height:1.5}
.pv-capture-secret{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.pv-capture-secret .pv-input{flex:1 1 160px;min-width:120px}
.pv-capture-footer{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:14px;padding-top:12px;border-top:1px solid var(--dsw-alias-border-l2)}
.pv-capture-note{color:var(--dsw-alias-label-tertiary);font-size:11px;line-height:1.5;max-width:310px}
.pv-capture-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
@media (max-width:640px){
.pv-capture-backdrop{padding:12px}
.pv-capture{max-height:94vh;padding:14px}
.pv-capture-footer{align-items:stretch;flex-direction:column}
.pv-capture-note{max-width:none}
.pv-capture-actions{justify-content:flex-end}
}
`;

    /** Small decorative shield. */
    function ShieldIcon({ size = 18 }) {
      return h('svg', {
        width: size,
        height: size,
        viewBox: '0 0 24 24',
        fill: 'none',
        'aria-hidden': true,
      },
      h('path', {
        d: 'M12 3 5 6v5.2c0 4.4 2.9 8.2 7 9.8 4.1-1.6 7-5.4 7-9.8V6l-7-3Z',
        stroke: 'currentColor',
        strokeWidth: 1.7,
        strokeLinejoin: 'round',
      }),
      h('path', {
        d: 'M9.5 12.2l1.8 1.8 3.5-3.8',
        stroke: 'currentColor',
        strokeWidth: 1.7,
        strokeLinecap: 'round',
        strokeLinejoin: 'round',
      }));
    }

    /** Small search glyph. */
    function SearchIcon() {
      return h('svg', { width: 13, height: 13, viewBox: '0 0 16 16', fill: 'none', 'aria-hidden': true },
        h('circle', { cx: 7, cy: 7, r: 4.6, stroke: 'currentColor', strokeWidth: 1.4 }),
        h('path', { d: 'm10.5 10.5 3 3', stroke: 'currentColor', strokeWidth: 1.4, strokeLinecap: 'round' }));
    }

    /** Request helper for the loopback management API. */
    async function request(path, body) {
      const response = await fetch(`/vault-api/${String(path).replace(/^\/+/, '')}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers: body === undefined ? { accept: 'application/json' } : { accept: 'application/json', 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store',
        credentials: 'same-origin',
      });
      let data;
      try {
        data = await response.json();
      } catch {
        data = null;
      }
      if (!response.ok) {
        const error = new Error(data?.message || `HTTP ${response.status}`);
        error.code = data?.error || 'HTTP_ERROR';
        throw error;
      }
      return data;
    }

    /** Format an ISO timestamp for the local UI. */
    function formatTime(value) {
      if (!value) return '—';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return String(value);
      return date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    /** One labeled field wrapper. */
    function Field({ label, hint, children }) {
      return h('label', { className: 'pv-field' },
        h('span', { className: 'pv-label' }, label),
        children,
        hint ? h('span', { className: 'pv-hint' }, hint) : null);
    }

    /** The settings section component. */
    function VaultPage({ t }) {
      const [status, setStatus] = useState(null);
      const [entries, setEntries] = useState([]);
      const [audit, setAudit] = useState([]);
      const [loading, setLoading] = useState(true);
      const [busy, setBusy] = useState(false);
      const [error, setError] = useState('');
      const [notice, setNotice] = useState('');
      const [query, setQuery] = useState('');
      const [setupPassword, setSetupPassword] = useState('');
      const [setupConfirm, setSetupConfirm] = useState('');
      const [unlockPassword, setUnlockPassword] = useState('');
      const [editor, setEditor] = useState(null);
      const [reveal, setReveal] = useState(null);
      const [showSecret, setShowSecret] = useState(false);
      const [deleteId, setDeleteId] = useState(null);

      const refresh = useCallback(async () => {
        try {
          const next = await request('status');
          setStatus(next);
          setError('');
          if (next.unlocked) {
            const [list, log] = await Promise.all([
              request('entries/list', {}),
              request('audit', { limit: 30 }),
            ]);
            setEntries(Array.isArray(list.entries) ? list.entries : []);
            setAudit(Array.isArray(log.entries) ? log.entries : []);
          } else {
            setEntries([]);
            setAudit([]);
          }
        } catch (err) {
          setError(err instanceof Error ? err.message : t('requestFailed'));
        } finally {
          setLoading(false);
        }
      }, [t]);

      useEffect(() => {
        refresh();
      }, [refresh]);

      useEffect(() => {
        if (!notice) return undefined;
        const timer = setTimeout(() => setNotice(''), 2500);
        return () => clearTimeout(timer);
      }, [notice]);

      const filtered = useMemo(() => {
        const value = query.trim().toLowerCase();
        if (value === '') return entries;
        return entries.filter((entry) => [
          entry.label,
          entry.username,
          entry.url,
          entry.accountHint,
          ...(entry.tags ?? []),
        ].join(' ').toLowerCase().includes(value));
      }, [entries, query]);

      const withBusy = async (fn) => {
        if (busy) return;
        setBusy(true);
        setError('');
        try {
          await fn();
        } catch (err) {
          setError(err instanceof Error ? err.message : t('requestFailed'));
        } finally {
          setBusy(false);
        }
      };

      const copy = async (value) => {
        try {
          if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable');
          await navigator.clipboard.writeText(String(value ?? ''));
          setNotice(t('copied'));
        } catch {
          setError(t('copyFailed'));
        }
      };

      const createVault = () => withBusy(async () => {
        if (setupPassword !== setupConfirm) {
          setError(t('passwordMismatch'));
          return;
        }
        await request('setup', { masterPassword: setupPassword });
        setSetupPassword('');
        setSetupConfirm('');
        await refresh();
      });

      const unlock = () => withBusy(async () => {
        await request('unlock', { masterPassword: unlockPassword });
        setUnlockPassword('');
        await refresh();
      });

      const lock = () => withBusy(async () => {
        await request('lock', {});
        setReveal(null);
        setEditor(null);
        await refresh();
      });

      const toggleAi = (entry) => withBusy(async () => {
        await request('entries/ai', { id: entry.id, enabled: !entry.aiEnabled });
        await refresh();
      });

      const toggleExec = (enabled) => withBusy(async () => {
        await request('settings/exec', { enabled });
        await refresh();
      });

      const openReveal = (entry) => withBusy(async () => {
        if (reveal?.id === entry.id) {
          setReveal(null);
          return;
        }
        const data = await request('entries/get', { id: entry.id, reveal: true });
        setReveal({ id: entry.id, data });
        setShowSecret(false);
      });

      const refreshTotp = () => withBusy(async () => {
        if (!reveal) return;
        const data = await request('entries/get', { id: reveal.id, reveal: true });
        setReveal({ id: reveal.id, data });
      });

      const startAdd = () => {
        setDeleteId(null);
        setReveal(null);
        setEditor({
          id: null,
          form: {
            label: '',
            username: '',
            password: '',
            url: '',
            notes: '',
            tags: '',
            totpSecret: '',
            authType: 'none',
            authKey: '',
            allowedHosts: '',
            allowInsecure: false,
            aiEnabled: true,
            clearPassword: false,
            clearTotp: false,
          },
        });
      };

      const startEdit = (entry) => {
        setDeleteId(null);
        setReveal(null);
        setEditor({
          id: entry.id,
          form: {
            label: entry.label ?? '',
            username: entry.username ?? '',
            password: '',
            url: entry.url ?? '',
            notes: entry.notes ?? '',
            tags: (entry.tags ?? []).join(', '),
            totpSecret: '',
            authType: entry.authType ?? 'none',
            authKey: entry.authKey ?? '',
            allowedHosts: (entry.allowedHosts ?? []).join(', '),
            allowInsecure: entry.allowInsecure === true,
            aiEnabled: entry.aiEnabled !== false,
            clearPassword: false,
            clearTotp: false,
            hasPassword: entry.hasPassword === true,
            hasTotp: entry.hasTotp === true,
          },
        });
      };

      const setField = (key, value) => {
        setEditor((current) => current === null ? current : ({
          ...current,
          form: { ...current.form, [key]: value },
        }));
      };

      const saveEntry = () => withBusy(async () => {
        if (!editor) return;
        if (String(editor.form.label).trim() === '') {
          setError(t('fieldLabelRequired'));
          return;
        }
        const payload = {
          label: editor.form.label,
          username: editor.form.username,
          url: editor.form.url,
          notes: editor.form.notes,
          tags: editor.form.tags,
          authType: editor.form.authType,
          authKey: editor.form.authKey,
          allowedHosts: editor.form.allowedHosts,
          allowInsecure: editor.form.allowInsecure,
          aiEnabled: editor.form.aiEnabled,
        };
        if (editor.id !== null) payload.id = editor.id;
        if (editor.form.password !== '') payload.password = editor.form.password;
        if (editor.form.clearPassword) payload.clearPassword = true;
        if (editor.form.clearTotp) payload.totpSecret = '';
        else if (editor.form.totpSecret !== '') payload.totpSecret = editor.form.totpSecret;
        await request('entries/save', { entry: payload });
        setEditor(null);
        await refresh();
      });

      const deleteEntry = (id) => withBusy(async () => {
        await request('entries/delete', { id });
        setDeleteId(null);
        setReveal(null);
        await refresh();
      });

      const statusPill = () => {
        if (status?.broken) return { className: 'pv-pill err', label: t('statusBroken') };
        if (!status?.configured) return { className: 'pv-pill', label: t('statusUnconfigured') };
        if (status.unlocked) return { className: 'pv-pill ok', label: t('statusUnlocked') };
        return { className: 'pv-pill warn', label: t('statusLocked') };
      };

      const pill = statusPill();
      const protection = status?.protection === 'dpapi'
        ? t('protectionDpapi')
        : status?.protection === 'password'
          ? t('protectionPassword')
          : t('protectionNone');

      const renderEditor = () => {
        if (!editor) return null;
        const form = editor.form;
        return h('section', { className: 'pv-card pv-editor' },
          h('div', { className: 'pv-editor-head' },
            h('h3', null, editor.id === null ? t('editorNew') : t('editorEdit')),
            h('button', { type: 'button', className: 'pv-btn ghost small', onClick: () => setEditor(null) }, t('cancel'))),
          h('div', { className: 'pv-form' },
            h('div', { className: 'pv-grid' },
              h(Field, { label: t('fieldLabel') },
                h('input', {
                  className: 'pv-input',
                  value: form.label,
                  maxLength: 200,
                  autoFocus: true,
                  onChange: (event) => setField('label', event.target.value),
                })),
              h(Field, { label: t('fieldUsername') },
                h('input', {
                  className: 'pv-input',
                  value: form.username,
                  autoComplete: 'off',
                  onChange: (event) => setField('username', event.target.value),
                }))),
            h('div', { className: 'pv-grid' },
              h(Field, {
                label: t('fieldPassword'),
                hint: editor.id === null ? null : t('fieldPasswordKeep'),
              },
              h('input', {
                className: 'pv-input',
                type: 'password',
                value: form.password,
                autoComplete: 'new-password',
                onChange: (event) => {
                  setField('password', event.target.value);
                  if (event.target.value !== '') setField('clearPassword', false);
                },
              })),
              h(Field, { label: t('fieldUrl') },
                h('input', {
                  className: 'pv-input',
                  value: form.url,
                  inputMode: 'url',
                  placeholder: 'https://example.com/login',
                  onChange: (event) => setField('url', event.target.value),
                }))),
            editor.id !== null && form.hasPassword
              ? h('label', { className: 'pv-check' },
                  h('input', {
                    type: 'checkbox',
                    checked: form.clearPassword,
                    onChange: (event) => setField('clearPassword', event.target.checked),
                  }),
                  h('span', null, t('clearPassword')))
              : null,
            editor.id !== null && form.hasTotp
              ? h('label', { className: 'pv-check' },
                  h('input', {
                    type: 'checkbox',
                    checked: form.clearTotp,
                    onChange: (event) => setField('clearTotp', event.target.checked),
                  }),
                  h('span', null, t('clearTotp')))
              : null,
            h('div', { className: 'pv-grid' },
              h(Field, { label: t('fieldAuthType') },
                h('select', {
                  className: 'pv-select',
                  value: form.authType,
                  onChange: (event) => setField('authType', event.target.value),
                },
                h('option', { value: 'none' }, t('authNone')),
                h('option', { value: 'basic' }, t('authBasic')),
                h('option', { value: 'bearer' }, t('authBearer')),
                h('option', { value: 'header' }, t('authHeader')),
                h('option', { value: 'query' }, t('authQuery')))),
              (form.authType === 'header' || form.authType === 'query')
                ? h(Field, { label: t('fieldAuthKey') },
                    h('input', {
                      className: 'pv-input',
                      value: form.authKey,
                      placeholder: form.authType === 'header' ? 'X-API-Key' : 'api_key',
                      onChange: (event) => setField('authKey', event.target.value),
                    }))
                : null),
            h('div', { className: 'pv-grid' },
              h(Field, { label: t('fieldTotp'), hint: t('fieldTotpHint') },
                h('input', {
                  className: 'pv-input',
                  value: form.totpSecret,
                  placeholder: editor.id !== null && form.hasTotp ? '••••••••' : 'JBSWY3DPEHPK3PXP',
                  autoComplete: 'off',
                  onChange: (event) => {
                    setField('totpSecret', event.target.value);
                    if (event.target.value !== '') setField('clearTotp', false);
                  },
                })),
              h(Field, { label: t('fieldTags') },
                h('input', {
                  className: 'pv-input',
                  value: form.tags,
                  placeholder: 'work, api',
                  onChange: (event) => setField('tags', event.target.value),
                }))),
            h(Field, { label: t('fieldAllowedHosts'), hint: t('fieldAllowedHostsHint') },
              h('input', {
                className: 'pv-input',
                value: form.allowedHosts,
                placeholder: 'api.example.com, *.example.com',
                onChange: (event) => setField('allowedHosts', event.target.value),
              })),
            h(Field, { label: t('fieldNotes') },
              h('textarea', {
                className: 'pv-textarea',
                value: form.notes,
                onChange: (event) => setField('notes', event.target.value),
              })),
            h('label', { className: 'pv-check' },
              h('input', {
                type: 'checkbox',
                checked: form.allowInsecure,
                onChange: (event) => setField('allowInsecure', event.target.checked),
              }),
              h('span', null, t('fieldAllowInsecure'))),
            h('label', { className: 'pv-check' },
              h('input', {
                type: 'checkbox',
                checked: form.aiEnabled,
                onChange: (event) => setField('aiEnabled', event.target.checked),
              }),
              h('span', null, t('fieldAi'))),
            h('div', { className: 'pv-actions' },
              h('button', {
                type: 'button',
                className: 'pv-btn primary',
                disabled: busy,
                onClick: saveEntry,
              }, busy ? t('saving') : t('save')),
              h('button', {
                type: 'button',
                className: 'pv-btn',
                disabled: busy,
                onClick: () => setEditor(null),
              }, t('cancel')))));
      };

      const renderReveal = (entry) => {
        if (reveal?.id !== entry.id) return null;
        const data = reveal.data;
        return h('div', { className: 'pv-reveal' },
          h('div', { className: 'pv-reveal-grid' },
            h('div', { className: 'pv-reveal-row' },
              h('span', null, t('account')),
              h('div', { className: 'pv-secret' },
                h('code', { className: 'pv-code' }, data.username || '—'),
                data.username ? h('button', {
                  type: 'button', className: 'pv-btn small', onClick: () => copy(data.username),
                }, t('copy')) : null)),
            h('div', { className: 'pv-reveal-row' },
              h('span', null, t('password')),
              h('div', { className: 'pv-secret' },
                h('code', { className: 'pv-code' }, showSecret ? (data.password || '—') : '••••••••'),
                h('button', {
                  type: 'button',
                  className: 'pv-btn small',
                  onClick: () => setShowSecret((value) => !value),
                }, showSecret ? t('hideSecret') : t('showSecret')),
                data.password ? h('button', {
                  type: 'button', className: 'pv-btn small', onClick: () => copy(data.password),
                }, t('copy')) : null)),
            data.totp ? h('div', { className: 'pv-reveal-row' },
              h('span', null, t('totp')),
              h('div', { className: 'pv-secret' },
                h('code', { className: 'pv-code' }, data.totp.code),
                h('span', { className: 'pv-hint' }, `${data.totp.secondsRemaining} ${t('totpRemaining')}`),
                h('button', {
                  type: 'button', className: 'pv-btn small', onClick: refreshTotp,
                }, t('refreshTotp')),
                h('button', {
                  type: 'button', className: 'pv-btn small', onClick: () => copy(data.totp.code),
                }, t('copy')))) : null),
          h('p', { className: 'pv-reveal-note' }, t('revealHint')));
      };

      const renderEntry = (entry) => {
        const isOpen = reveal?.id === entry.id;
        return h('div', { className: 'pv-entry', key: entry.id },
          h('div', { className: 'pv-entry-head' },
            h('div', { className: 'pv-entry-main' },
              h('div', { className: 'pv-entry-title' },
                h('span', { className: 'pv-name' }, entry.label),
                (entry.tags ?? []).map((tag) => h('span', { className: 'pv-tag', key: `${entry.id}-${tag}` }, tag)),
                entry.aiEnabled ? null : h('span', { className: 'pv-off' }, t('aiOff'))),
              h('div', { className: 'pv-meta' },
                h('span', null, entry.username || t('noUsername')),
                h('span', { className: 'pv-sep' }, '·'),
                h('span', null, entry.url || t('noUrl')),
                h('span', { className: 'pv-sep' }, '·'),
                h('span', null, `${t('updated')} ${formatTime(entry.updatedAt)}`))),
            h('div', { className: 'pv-entry-actions' },
              h('label', {
                className: 'pv-switch',
                title: entry.aiEnabled ? t('aiOn') : t('aiOff'),
              },
              h('input', {
                type: 'checkbox',
                checked: entry.aiEnabled,
                onChange: () => toggleAi(entry),
                'aria-label': t('aiAccess'),
              }),
              h('span')),
              h('button', {
                type: 'button',
                className: 'pv-btn small',
                onClick: () => openReveal(entry),
              }, isOpen ? t('hide') : t('show')),
              h('button', {
                type: 'button',
                className: 'pv-btn small',
                onClick: () => startEdit(entry),
              }, t('edit')),
              h('button', {
                type: 'button',
                className: 'pv-btn danger small',
                onClick: () => setDeleteId(deleteId === entry.id ? null : entry.id),
              }, t('delete')))),
          renderReveal(entry),
          deleteId === entry.id ? h('div', { className: 'pv-delete' },
            h('p', null, h('strong', null, `${t('deleteConfirm')} `), t('deleteHint')),
            h('div', { className: 'pv-actions' },
              h('button', {
                type: 'button', className: 'pv-btn danger', disabled: busy, onClick: () => deleteEntry(entry.id),
              }, t('delete')),
              h('button', {
                type: 'button', className: 'pv-btn', disabled: busy, onClick: () => setDeleteId(null),
              }, t('cancel')))) : null);
      };

      const renderContent = () => {
        if (loading) {
          return h('div', { className: 'pv-card pv-empty' }, t('loading'));
        }
        if (status?.broken) {
          return h('section', { className: 'pv-card' },
            h('h3', null, t('brokenTitle')),
            h('p', null, t('brokenIntro')),
            h('p', { style: { marginTop: 8 } }, t('brokenHint')),
            h('div', { className: 'pv-privacy', style: { marginTop: 10 } },
              h('span', null, `${t('fileLocation')}: `),
              h('code', { className: 'pv-path' }, status.vaultPath),
              status.error ? h('span', { className: 'pv-error-text' }, status.error) : null));
        }
        if (!status?.configured) {
          return h('section', { className: 'pv-card' },
            h('h3', null, t('setupTitle')),
            h('p', null, t('setupIntro')),
            h('div', { className: 'pv-form', style: { maxWidth: 420 } },
              h(Field, { label: t('setupPassword'), hint: t('setupPasswordHint') },
                h('input', {
                  className: 'pv-input',
                  type: 'password',
                  value: setupPassword,
                  autoComplete: 'new-password',
                  onChange: (event) => setSetupPassword(event.target.value),
                })),
              setupPassword !== '' ? h(Field, { label: t('setupConfirm') },
                h('input', {
                  className: 'pv-input',
                  type: 'password',
                  value: setupConfirm,
                  autoComplete: 'new-password',
                  onChange: (event) => setSetupConfirm(event.target.value),
                })) : null,
              h('div', { className: 'pv-actions' },
                h('button', {
                  type: 'button',
                  className: 'pv-btn primary',
                  disabled: busy,
                  onClick: createVault,
                }, busy ? t('creating') : t('createVault')))),
            h('div', { className: 'pv-privacy', style: { marginTop: 12 } },
              h('span', null, h('strong', null, `${t('privacyTitle')}: `), t('privacyNote')),
              h('span', null, t('notConfiguredHint'))));
        }
        if (!status.unlocked) {
          return h('section', { className: 'pv-card' },
            h('h3', null, t('unlockTitle')),
            h('p', null, t('unlockIntro')),
            h('div', { className: 'pv-form', style: { maxWidth: 420 } },
              status.autoUnlock
                ? h('div', { className: 'pv-actions' },
                    h('button', {
                      type: 'button',
                      className: 'pv-btn primary',
                      disabled: busy,
                      onClick: unlock,
                    }, busy ? t('unlocking') : t('autoUnlockAction')))
                : h(React.Fragment, null,
                    h(Field, { label: t('masterPassword') },
                      h('input', {
                        className: 'pv-input',
                        type: 'password',
                        value: unlockPassword,
                        autoComplete: 'current-password',
                        autoFocus: true,
                        onChange: (event) => setUnlockPassword(event.target.value),
                        onKeyDown: (event) => {
                          if (event.key === 'Enter') unlock();
                        },
                      })),
                    h('div', { className: 'pv-actions' },
                      h('button', {
                        type: 'button',
                        className: 'pv-btn primary',
                        disabled: busy,
                        onClick: unlock,
                      }, busy ? t('unlocking') : t('unlockAction'))))),
            h('p', { className: 'pv-hint', style: { marginTop: 10 } }, t('lockedHint')));
        }
        return h(React.Fragment, null,
          h('div', { className: 'pv-toolbar' },
            h('div', { className: 'pv-actions' },
              h('button', {
                type: 'button',
                className: 'pv-btn primary',
                onClick: startAdd,
              }, `+ ${t('addEntry')}`)),
            h('div', { className: 'pv-search' },
              h(SearchIcon),
              h('input', {
                className: 'pv-input',
                value: query,
                placeholder: t('search'),
                'aria-label': t('search'),
                onChange: (event) => setQuery(event.target.value),
              }))),
          renderEditor(),
          h('section', { className: 'pv-card pv-card-tight' },
            filtered.length === 0
              ? h('div', { className: 'pv-empty' },
                  h('div', null, query.trim() === '' ? t('noEntries') : t('noMatches')),
                  query.trim() === '' && entries.length === 0
                    ? h('div', { className: 'pv-actions', style: { justifyContent: 'center', marginTop: 12 } },
                        h('button', { type: 'button', className: 'pv-btn primary', onClick: startAdd }, t('addFirst')))
                    : null)
              : h('div', { className: 'pv-list' }, filtered.map(renderEntry))),
          h('details', { className: 'pv-audit' },
            h('summary', null, t('advanced')),
            h('div', { className: 'pv-form', style: { marginTop: 8 } },
              h('label', { className: 'pv-check' },
                h('input', {
                  type: 'checkbox',
                  checked: status.allowExec === true,
                  disabled: busy,
                  onChange: (event) => toggleExec(event.target.checked),
                }),
                h('span', null, t('allowExec'))),
              h('p', {
                className: 'pv-hint',
                style: status.allowExec ? { color: 'var(--dsw-alias-state-warn-primary)' } : undefined,
              }, status.allowExec ? t('allowExecOn') : t('allowExecHint')))),
          h('details', { className: 'pv-audit' },
            h('summary', null, t('audit')),
            audit.length === 0
              ? h('div', { className: 'pv-audit-empty' }, t('auditEmpty'))
              : h('div', { className: 'pv-audit-list' }, audit.map((row, index) => h('div', {
                  className: 'pv-audit-row',
                  key: `${row.at}-${index}`,
                },
                h('span', null, formatTime(row.at)),
                h('code', null, row.action),
                h('span', null, row.entryLabel || '—'))))));
      };

      if (status === null && error !== '') {
        return h('div', { className: 'pv-root' },
          h('style', null, css),
          h('div', { className: 'pv-banner err' }, error),
          h('div', { className: 'pv-actions' },
            h('button', { type: 'button', className: 'pv-btn', onClick: refresh }, t('refresh'))));
      }

      return h('div', { className: 'pv-root' },
        h('style', null, css),
        h('div', { className: 'pv-head' },
          h('div', { className: 'pv-heading' },
            h('div', { className: 'pv-mark' }, h(ShieldIcon)),
            h('div', null,
              h('h2', { className: 'pv-title' }, t('title')),
              h('p', { className: 'pv-subtitle' }, t('subtitle')))),
          h('div', { className: 'pv-head-actions' },
            h('span', { className: pill.className }, pill.label),
            status?.configured ? h('span', { className: 'pv-pill' }, protection) : null,
            h('button', {
              type: 'button', className: 'pv-btn small', disabled: loading || busy, onClick: refresh,
            }, t('refresh')),
            status?.unlocked ? h('button', {
              type: 'button', className: 'pv-btn small', disabled: busy, onClick: lock,
            }, t('lock')) : null)),
        error ? h('div', { className: 'pv-banner err' }, error) : null,
        notice ? h('div', { className: 'pv-banner ok' }, notice) : null,
        status?.configured ? h('div', { className: 'pv-privacy' },
          h('span', null, h('strong', null, `${t('fileLocation')}: `), h('code', { className: 'pv-path' }, status.vaultPath)),
          h('span', null, h('strong', null, `${t('privacyTitle')}: `), t('privacyNote')),
          h('span', null, t('securityNote'))) : null,
        renderContent());
    }

    /** Secure one-time credential prompt; always mounted so the agent can ask at any time. */
    function CaptureOverlay({ t }) {
      const [pending, setPending] = useState(null);
      const [form, setForm] = useState(null);
      const [busy, setBusy] = useState(false);
      const [error, setError] = useState('');
      const [showSecret, setShowSecret] = useState(false);
      const tokenRef = useRef(null);

      useEffect(() => {
        let alive = true;
        const tick = async () => {
          try {
            const data = await request('capture/pending');
            if (!alive) return;
            const next = data.request ?? null;
            if (next === null) {
              if (tokenRef.current !== null) {
                tokenRef.current = null;
                setPending(null);
                setForm(null);
                setBusy(false);
                setError('');
              }
              return;
            }
            if (tokenRef.current === next.token) return;
            tokenRef.current = next.token;
            setPending(next);
            setForm({
              label: next.label ?? '',
              username: next.username ?? '',
              password: '',
              url: next.url ?? '',
              notes: next.notes ?? '',
              totpSecret: '',
              authType: next.authType ?? 'none',
              authKey: next.authKey ?? '',
              allowedHosts: Array.isArray(next.allowedHosts)
                ? next.allowedHosts.join(', ')
                : (next.allowedHosts ?? ''),
              aiEnabled: true,
            });
            setError('');
            setShowSecret(false);
          } catch {
            // The Host may be restarting; the next poll retries.
          }
        };
        tick();
        const timer = setInterval(tick, 1500);
        return () => {
          alive = false;
          clearInterval(timer);
        };
      }, []);

      const setField = (key, value) => {
        setForm((current) => current === null ? current : ({ ...current, [key]: value }));
      };

      const cancel = async () => {
        if (!pending || busy) return;
        setBusy(true);
        try {
          await request('capture/cancel', { token: pending.token });
        } catch {
          // The prompt may already have expired.
        } finally {
          tokenRef.current = null;
          setPending(null);
          setForm(null);
          setBusy(false);
          setError('');
        }
      };

      const save = async () => {
        if (!pending || !form || busy) return;
        if (String(form.label).trim() === '' || String(form.password) === '') {
          setError(t('captureRequired'));
          return;
        }
        setBusy(true);
        setError('');
        try {
          await request('capture/complete', {
            token: pending.token,
            entry: {
              label: form.label,
              username: form.username,
              password: form.password,
              url: form.url,
              notes: form.notes,
              totpSecret: form.totpSecret,
              authType: form.authType,
              authKey: form.authKey,
              allowedHosts: form.allowedHosts,
              allowInsecure: false,
              aiEnabled: form.aiEnabled,
            },
          });
          tokenRef.current = null;
          setPending(null);
          setForm(null);
        } catch (err) {
          setError(err instanceof Error ? err.message : t('captureFailed'));
        } finally {
          setBusy(false);
        }
      };

      if (pending === null || form === null) return null;

      return h('div', { className: 'pv-capture-backdrop' },
        h('style', null, css + captureCss),
        h('div', {
          className: 'pv-capture',
          role: 'dialog',
          'aria-modal': 'true',
          'aria-labelledby': 'pv-capture-title',
          onKeyDown: (event) => {
            if (event.key === 'Escape') {
              event.preventDefault();
              if (!busy) cancel();
            }
          },
        },
        h('div', { className: 'pv-capture-head' },
          h('div', { className: 'pv-capture-heading' },
            h('div', { className: 'pv-capture-mark' }, h(ShieldIcon)),
            h('div', null,
              h('h2', { className: 'pv-capture-title', id: 'pv-capture-title' }, t('captureTitle')),
              h('p', { className: 'pv-capture-intro' }, t('captureIntro')))),
          h('button', {
            type: 'button',
            className: 'pv-capture-close',
            'aria-label': t('captureClose'),
            disabled: busy,
            onClick: cancel,
          }, '×')),
        h('p', { className: 'pv-capture-warning' }, t('captureVerify')),
        pending.purpose ? h('div', { className: 'pv-capture-purpose' },
          h('strong', null, `${t('capturePurpose')}: `), pending.purpose) : null,
        error ? h('div', { className: 'pv-capture-error' }, error) : null,
        h('div', { className: 'pv-form' },
          h('div', { className: 'pv-grid' },
            h(Field, { label: t('captureName') },
              h('input', {
                className: 'pv-input',
                value: form.label,
                maxLength: 200,
                autoFocus: form.label === '',
                onChange: (event) => setField('label', event.target.value),
              })),
            h(Field, { label: t('captureUsername') },
              h('input', {
                className: 'pv-input',
                value: form.username,
                autoComplete: 'off',
                onChange: (event) => setField('username', event.target.value),
              }))),
          h('div', { className: 'pv-grid' },
            h(Field, { label: t('capturePassword') },
              h('div', { className: 'pv-capture-secret' },
                h('input', {
                  className: 'pv-input',
                  type: showSecret ? 'text' : 'password',
                  value: form.password,
                  autoComplete: 'new-password',
                  autoFocus: form.label !== '',
                  onChange: (event) => setField('password', event.target.value),
                  onKeyDown: (event) => {
                    if (event.key === 'Enter') {
                      event.preventDefault();
                      save();
                    }
                  },
                }),
                h('button', {
                  type: 'button',
                  className: 'pv-btn small',
                  onClick: () => setShowSecret((value) => !value),
                }, showSecret ? t('captureHide') : t('captureShow')))),
            h(Field, { label: t('captureUrl') },
              h('input', {
                className: 'pv-input',
                value: form.url,
                inputMode: 'url',
                placeholder: 'https://example.com/login',
                onChange: (event) => setField('url', event.target.value),
              }))),
          h('div', { className: 'pv-grid' },
            h(Field, { label: t('captureAuthType') },
              h('select', {
                className: 'pv-select',
                value: form.authType,
                onChange: (event) => setField('authType', event.target.value),
              },
              h('option', { value: 'none' }, t('authNone')),
              h('option', { value: 'basic' }, t('authBasic')),
              h('option', { value: 'bearer' }, t('authBearer')),
              h('option', { value: 'header' }, t('authHeader')),
              h('option', { value: 'query' }, t('authQuery')))),
            (form.authType === 'header' || form.authType === 'query')
              ? h(Field, { label: t('captureAuthKey') },
                  h('input', {
                    className: 'pv-input',
                    value: form.authKey,
                    placeholder: form.authType === 'header' ? 'X-API-Key' : 'api_key',
                    onChange: (event) => setField('authKey', event.target.value),
                  }))
              : null),
          h('div', { className: 'pv-grid' },
            h(Field, { label: t('captureTotp') },
              h('input', {
                className: 'pv-input',
                value: form.totpSecret,
                placeholder: 'JBSWY3DPEHPK3PXP',
                autoComplete: 'off',
                onChange: (event) => setField('totpSecret', event.target.value),
              })),
            h(Field, { label: t('captureNotes') },
              h('textarea', {
                className: 'pv-textarea',
                value: form.notes,
                onChange: (event) => setField('notes', event.target.value),
              }))),
          h('label', { className: 'pv-check' },
            h('input', {
              type: 'checkbox',
              checked: form.aiEnabled,
              onChange: (event) => setField('aiEnabled', event.target.checked),
            }),
            h('span', null, t('captureAi'))),
          form.aiEnabled ? null : h('p', { className: 'pv-hint' }, t('captureAiOff'))),
        h('div', { className: 'pv-capture-footer' },
          h('div', { className: 'pv-capture-note' },
            h('div', null, t('captureSecure')),
            h('div', null, t('captureExpires'))),
          h('div', { className: 'pv-capture-actions' },
            h('button', {
              type: 'button',
              className: 'pv-btn',
              disabled: busy,
              onClick: cancel,
            }, t('captureCancel')),
            h('button', {
              type: 'button',
              className: 'pv-btn primary',
              disabled: busy,
              onClick: save,
            }, busy ? t('captureSaving') : t('captureSave'))))));
    }

    /** Register the settings section and the always-available capture overlay. */
    function apply(ctx) {
      const t = ctx.locale.bind(NS);
      ctx.effect(() => ctx.locale.register(NS, { en, zh }), 'password-vault: locale');
      ctx.slots.inject('settings.section', () => ctx.slots.register({
        name: 'settings.section',
        id: 'password-vault',
        order: 25,
        label: () => t('nav'),
        locale: NS,
      }, (props) => h(VaultPage, { ...props, t })));
      ctx.slots.inject('shell.overlay', () => ctx.slots.register({
        name: 'shell.overlay',
        id: 'password-vault-capture',
        order: 50,
        locale: NS,
      }, (props) => h(CaptureOverlay, { ...props, t })));
    }

    return { inject: ['slots', 'locale'], apply };
  },
});
