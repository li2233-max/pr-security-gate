# PR 安全审查门禁

这是一个可复用的 GitHub Actions 中心仓库。它读取项目 PR 的 diff，调用 AI 生成固定格式的 Code Review 报告，并按 P0/P1/P2 决定检查是否通过。

- P0：`BLOCK`，检查失败，禁止合并。
- P1/P2：`PASS`，可合并，报告仅显示 `技术债：N 项`。
- 标准 `pull_request` 入口本身不是风险项。

## 新项目快速接入

在目标项目创建 `.github/workflows/pr-ai-review.yml`：

```yaml
name: PR AI Security Review

on:
  pull_request:
    branches: [dev, main]
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  security-review:
    name: pr-security-gate
    uses: li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v2
    secrets:
      DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
```

然后在目标项目的 `Settings → Secrets and variables → Actions → Secrets` 新建 `DEEPSEEK_API_KEY`。不要把 Key 写入代码、工作流文件、PR、Issue 或日志。

创建以 `dev` 或 `main` 为 base 的 PR 后，`pr-security-gate` 会自动生成 Code Review 报告。首次检查成功后，在目标项目的 `Settings → Branches → Branch protection rules` 启用 **Require status checks to pass before merging**，并选择实际显示的 `pr-security-gate` 检查。

## 工作方式

项目仓库只保留上面的薄入口工作流，不复制审查脚本、规则或 Skill。中心工作流只读取 PR diff 和中心规则，不检出、安装或执行 PR 分支代码。

审查报告包含：仓库、分支、提交、敏感面、已验证证据、风险项和技术债数量。

## 详细接入说明

供 AI 执行的完整步骤见 [references/new-project-integration.md](references/new-project-integration.md)。

## 版本

新项目使用 `@v2`。中心仓库发布新版本后，再按需将入口工作流升级到新的标签。
