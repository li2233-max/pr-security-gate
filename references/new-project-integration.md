# 新项目接入中心安全与架构门禁

目标仓库只保留薄入口和本项目自己的架构契约/债务账本；中心审查脚本、Skill 和通用规则不复制过去。

## 1. 准备 base 分支上的项目规则

把以下模板复制到目标仓库并先合入受保护 base：

- [templates/architecture.json](../templates/architecture.json) → `.pr-security-gate/architecture.json`
- [templates/debt.json](../templates/debt.json) → `.pr-security-gate/debt.json`

必须按真实目录、导入形式和框架定制 `components`、marker、资源规则、预算及 `maxAgeDays`。模板中的 `security-auth-tests`、`tenant-isolation-tests`、`transaction-idempotency-tests`、`deployment-boundary-check` 和 `architecture-owner-approval` 都是占位名称；如果对应检查并不存在，门禁会阻断。要么创建真实检查，要么替换成现有检查名称。

首次启用时，把仓库当前尚未解决的 P1/P2 填入债务账本作为基线，不要用空账本假装历史债务为零。格式和策略见 [架构契约说明](architecture-contract.md)。

## 2. 保护裁判规则

用 CODEOWNERS 保护契约、账本和入口工作流，例如：

```text
/.pr-security-gate/architecture.json  @architecture-team
/.pr-security-gate/debt.json          @architecture-team
/.github/workflows/pr-ai-review.yml   @security-team
```

同时配置由 base 中受保护且候选未修改的 workflow 产生的负责人审批 Check Run，并让 `contractChangeCheck` 指向它。门禁会核验 candidate SHA、Check Suite 和 workflow run；同名 legacy status 不算审批，CODEOWNERS 审批本身也不会自动生成任意命名的 check。

## 3. 添加标准入口

在目标项目创建 `.github/workflows/pr-ai-review.yml`，内容直接采用 [标准入口模板](../templates/project-pr-ai-review.yml)。模板同时监听：

- `pull_request`：单 PR 预审。
- `merge_group / checks_requested`：Merge Queue 组合候选复审。

模板显式传入 `DEEPSEEK_API_KEY`，不使用 `secrets: inherit`，并引用：

```text
li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v4
```

保留模板中的最小权限：`contents: read`、`checks: read`、`statuses: read`、`actions: read`、`security-events: read` 和用于更新 PR 评论的 `pull-requests: write`。可复用工作流不能提升调用方权限；如果目标项目入口没有授予某项读取权限，中心 workflow 即使声明它也无法恢复。

中心流程只静态读取固定 SHA 上的 diff、受影响源码切片，以及 GitHub 的 PR 正文、Check Runs、commit statuses 和 Code Scanning analysis/开放 alert 元数据，不安装依赖、不执行 PR 分支代码。`actions: read` 用于核验 GitHub Actions Check 对应的 workflow run 和 workflow 来源，`security-events: read` 用于读取扫描元数据。

所有可验证证据必须绑定当前 candidate SHA。PR 正文只作为作者声明，不能因写有 `PASS`、测试名、401/403 或扫描链接就被升级为已验证证据。Code Scanning API 返回 403/404、没有当前 SHA 的 analysis 或 SHA 不匹配时，记为 `unavailable`，不能声称扫描通过。

门禁不会下载完整 Actions 日志、原始 SARIF 或 artifact，也不会访问 Check/PR 中的外部链接来抓取 HTTP 内容。不要在 PR 正文或 Check 摘要中粘贴 Secret、Token、Cookie、Authorization 等敏感 Header 或完整请求/响应；只保留脱敏摘要和 GitHub Check 链接。

## 4. 配置 Secret

在目标项目的 `Settings → Secrets and variables → Actions → Secrets` 新建：

```text
DEEPSEEK_API_KEY
```

不要把 Key 写入 YAML、代码、PR、Issue 或日志。通知地址若由目标项目额外使用，也应作为 Secret 显式映射，不能硬编码；当前中心模板不要求通知地址。

## 5. 配置合并保护

先让检查成功运行一次，再进入 `Settings → Branches → Branch protection rules` 或 Rulesets：

1. 把实际显示的 `pr-security-gate` 设为 required status check。
2. 优先启用 GitHub Merge Queue；否则至少启用分支合并前必须基于最新 base。
3. 对契约和债务账本要求 CODEOWNERS/架构负责人审批及对应命名检查。

仅监听 `pull_request` 不能验证排队 PR 的组合状态；使用 [GitHub Merge Queue](https://docs.github.com/en/repositories/configuring-branches-and-merges/in-your-repository/configuring-pull-request-merges/managing-a-merge-queue) 时，required workflow 必须同时监听 `merge_group`。

## 6. 验收

至少验证：

- 新 commit 或 base SHA 改变后，旧 PASS 不再发布或复用。
- PR A、PR B 对旧 base 单独可通过，但队列候选 A+B 违规时 `architectureGate=BLOCK`。
- 修改架构契约放宽限制时，缺少负责人检查会阻断。
- 历史已有违规不阻断无关 PR；新增同类违规按 `ratchet` 或预算策略阻断。
- 本 PR P1/P2 已登记进候选账本；报告同时显示本 PR 数量与全仓累计数量。

## 7. 版本迁移

`@v3` 保持原行为，不移动旧标签。先把契约、真实债务基线、审批检查和 Merge Queue 配置合入 base，再把入口从 `@v3` 升到 `@v4`。本仓库代码合并后仍需由维护者实际发布 `v4` tag，目标项目才能引用它。
