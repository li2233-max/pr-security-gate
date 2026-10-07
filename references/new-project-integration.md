# 新项目接入中心安全与架构门禁

目标仓库只保留薄入口和本项目自己的架构契约/债务账本；中心审查脚本、Skill 和通用规则不复制过去。

## 1. 准备 base 分支上的项目规则

把以下模板复制到目标仓库并先合入受保护 base：

- [templates/architecture.json](../templates/architecture.json) → `.pr-security-gate/architecture.json`
- [templates/debt.json](../templates/debt.json) → `.pr-security-gate/debt.json`

必须按真实目录、导入形式和框架定制 `components`、marker、资源规则、组合规则、`criticalPaths` 的审查路径、预算及 `maxAgeDays`。关键路径用于纳入候选源码切片，交给 AI 分析业务风险。

首次启用时，把仓库当前尚未解决的 P1/P2 填入债务账本作为基线，不要用空账本假装历史债务为零。格式和策略见 [架构契约说明](architecture-contract.md)。

## 2. 保护裁判规则

用 CODEOWNERS 保护契约、账本和入口工作流，例如：

```text
/.pr-security-gate/architecture.json  @architecture-team
/.pr-security-gate/debt.json          @architecture-team
/.github/workflows/pr-ai-review.yml   @security-team
```

在目标项目的 GitHub 合并规则中启用 CODEOWNERS 负责人审批；中心脚本始终按 base 版本契约评估候选代码。

## 3. 添加标准入口

在目标项目创建 `.github/workflows/pr-ai-review.yml`，内容直接采用 [标准入口模板](../templates/project-pr-ai-review.yml)。模板同时监听：

- `pull_request`：单 PR 预审。
- `merge_group / checks_requested`：Merge Queue 组合候选复审。

模板显式传入 `DEEPSEEK_API_KEY`，不使用 `secrets: inherit`，并引用：

```text
li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v4
```

保留模板中的最小权限：`contents: read` 和 `pull-requests: write`。它们用于读取固定 SHA 的代码、契约和债务账本，以及更新 PR 评论。

中心流程只静态读取固定 SHA 的 diff、契约覆盖的源码和变更文件，以及 PR 描述，不安装依赖、不执行 PR 分支代码。AI 根据实际改动和候选合并态判断上线风险；不采集独立 CI、扫描或生产配置检查结果，缺少这些结果本身不阻断。

PR 正文是作者声明，不能替代代码分析。请勿粘贴 Secret、Token、Cookie、Authorization 等敏感凭据；报告只保留脱敏后的定位与行为依据。

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
3. 对契约和债务账本要求 CODEOWNERS/架构负责人审批。

仅监听 `pull_request` 不能验证排队 PR 的组合状态；使用 [GitHub Merge Queue](https://docs.github.com/en/repositories/configuring-branches-and-merges/in-your-repository/configuring-pull-request-merges/managing-a-merge-queue) 时，required workflow 必须同时监听 `merge_group`。

## 6. 验收

至少验证：

- 新 commit 或 base SHA 改变后，旧 PASS 不再发布或复用。
- PR A、PR B 对旧 base 单独可通过，但队列候选 A+B 违规时 `architectureGate=BLOCK`。
- 修改架构契约放宽限制时，仍按 base 规则审查，负责人审批由 GitHub 合并规则执行。
- 历史已有违规不阻断无关 PR；新增同类违规按 `ratchet` 或预算策略阻断。
- 本 PR P1/P2 已登记进候选账本；报告同时显示本 PR 数量与全仓累计数量。

## 7. 版本迁移

`@v3` 保持原行为，不移动旧标签。先把契约、真实债务基线、CODEOWNERS 和 Merge Queue 配置合入 base，再把入口从 `@v3` 升到 `@v4`。本仓库代码合并后仍需由维护者实际发布 `v4` tag，目标项目才能引用它。
