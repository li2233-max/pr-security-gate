# 新项目接入中心 PR 安全审查（供 AI 执行）

当用户要求为一个新的 GitHub 项目接入 `pr-security-gate` 时，按本说明执行。目标项目只保留一个薄工作流；不复制审查脚本或规则文件。

## 接入前确认

1. 确认目标仓库、目标分支和用户授权。默认审查以 `dev` 或 `main` 为 base 的 PR；若项目使用其他目标分支，先按项目实际分支修改触发器。
2. 检查目标仓库的 `.github/workflows/`，避免重复创建同名审查工作流。
3. 不接收、不打印、不写入 API Key。由仓库管理员在 GitHub Secret 中配置 `DEEPSEEK_API_KEY`。

## 创建项目入口

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

concurrency:
  group: pr-ai-review-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  security-review:
    name: pr-security-gate
    uses: li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v2
    secrets:
      DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
```

`pull_request` 是本中心的标准入口，本身不作为 P0/P1/P2 风险或技术债。入口工作流不检出、安装或执行 PR 分支代码；中心工作流只读取 PR diff 并生成 Code Review 报告。

## 配置 GitHub Secret

指导仓库管理员进入 `Settings → Secrets and variables → Actions → Secrets`，创建 repository secret：

```text
DEEPSEEK_API_KEY
```

只显式映射这一项 Secret；不要使用 `secrets: inherit`，不要把 Key 写进 YAML、代码、日志、Issue 或 PR。

## 验证接入

1. 将入口工作流提交到功能分支。
2. 创建一个以目标分支为 base 的内部 PR。
3. 在 PR 的 Checks/Actions 中确认 `pr-security-gate` 已运行。
4. 在 PR Conversation 中确认出现以 `Code Review 完成` 开头的固定报告。
5. 推送一个新的 commit，确认同一份报告被更新。若检查失败，先读取 Actions 日志并修复入口配置、Secret 名称或模型调用问题。

## 启用强制合并门禁

首次成功运行后，指导管理员进入 `Settings → Branches → Branch protection rules`，为目标分支启用 **Require status checks to pass before merging**，并勾选实际显示的 `pr-security-gate` 检查。

`BLOCK`、模型调用失败或报告格式无效会使检查失败；只有 P1/P2 时检查通过，报告显示 `技术债：N 项`。

## 版本升级

新项目默认引用 `@v2`。中心仓库发布新版本后，按用户授权将入口中的版本改为新标签，例如从 `@v2` 改为 `@v3`；不要修改已发布的旧标签。
