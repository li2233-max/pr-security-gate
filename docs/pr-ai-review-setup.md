# 项目接入 PR AI 安全审查

`li2233-max/pr-security-gate` 是中心规则仓库：它保存审查规则、固定输出模板、审查脚本和可复用 GitHub Actions 工作流。项目仓库不复制这些文件，只保留一个入口工作流。

## 1. 添加项目入口

在目标项目新建 `.github/workflows/pr-ai-review.yml`，内容与 [模板](../templates/project-pr-ai-review.yml) 相同：

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
    uses: li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v3
    secrets:
      DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
```

项目入口只负责触发和传递本项目的 Secret；它不检出、安装或执行 PR 分支代码。

## 2. 配置 API Key

在每个接入项目中进入 `Settings → Secrets and variables → Actions → Secrets`，新建 repository secret：

```text
DEEPSEEK_API_KEY
```

不要将 Key 写入 YAML、代码、PR、Issue 或日志。这里使用显式映射而不是 `secrets: inherit`，因此中心工作流只能收到这一项 Secret。

## 3. 验证

以 `dev` 或 `main` 为 base 创建一个内部 PR。检查中应出现 `pr-security-gate`，PR Conversation 中应出现以 `Code Review 完成` 开头的固定报告。推送新的 commit 会更新同一条报告。

## 4. 分支保护

先让该检查成功运行一次，再进入 `Settings → Branches → Branch protection rules`，为 `dev` 和 `main` 开启 **Require status checks to pass before merging**，并选择页面实际显示的 `pr-security-gate` 检查。此后 `BLOCK`、模型调用失败或报告格式无效都会阻止合并；仅有 P1/P2 时检查通过，报告只显示 `技术债：N 项`。

## 5. `pull_request` 标准入口

当前模板固定使用 `pull_request`，因此向 `dev` 或 `main` 的首次 PR 也会立即执行。中心规则将它视为标准入口：仅使用该触发器不会产生 P0/P1/P2 风险项或技术债。中心工作流只读取 PR diff 和中心规则，不检出、安装或执行 PR 分支代码。

## 6. 更新中心规则

中心仓库修复或增强后，测试通过并发布新版本标签，例如 `v4`。项目把 `@v3` 改为 `@v4` 即可升级；保持 `@v3` 则继续使用当前稳定版本。
