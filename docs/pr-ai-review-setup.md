# 项目接入 PR 安全与架构门禁

`li2233-max/pr-security-gate` 是中心规则仓库。目标项目只保留标准入口，以及属于该项目的 `.pr-security-gate/architecture.json` 和 `.pr-security-gate/debt.json`。

## 标准入口

把 [项目入口模板](../templates/project-pr-ai-review.yml) 复制为目标项目的 `.github/workflows/pr-ai-review.yml`。它引用：

```text
li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v4
```

入口同时监听 `pull_request` 与 `merge_group` 的 `checks_requested`，后者用于 GitHub Merge Queue。目标项目必须显式映射 `DEEPSEEK_API_KEY`，不要使用 `secrets: inherit`。

入口仅声明 `contents: read` 和 `pull-requests: write`，分别用于读取固定 SHA 的代码、契约和债务账本，以及发布或更新 PR 评论。

## AI 审查范围

AI 分析实际 diff 和候选合并后的代码，判断安全、业务正确性及上线风险。源码切片覆盖项目契约指定的路径和本次变更中仍存在的文件；同时比较 base/candidate 架构和累计技术债。

独立 CI 验证已移除，不采集 Check Runs、legacy statuses 或 Code Scanning，也不要求密钥扫描、依赖漏洞审计或生产配置检查结果。缺少测试或扫描结果本身不阻断。PR 描述是作者声明；未知信息写“未提供”，不编造测试结果。中心流程不安装依赖、不执行 PR 分支代码。

## 项目架构契约

先按项目实际情况定制并合入 base：

- [架构模板](../templates/architecture.json) → `.pr-security-gate/architecture.json`
- [债务模板](../templates/debt.json) → `.pr-security-gate/debt.json`

按项目定制契约中的路径和规则。契约修改使用 base 版本规则评估；债务账本应从当前真实基线开始，不能把历史问题清零。

v4 不提供“未配置兼容放行”：受保护 base 缺少任一基线文件都会 `BLOCK`。因此必须先通过旧门禁或人工审批把契约与债务基线合入 base，再把项目入口升级到 `@v4`。

## GitHub 设置

1. 在 `Settings → Secrets and variables → Actions → Secrets` 新建 `DEEPSEEK_API_KEY`。
2. 先运行一次门禁，再到 `Settings → Branches → Branch protection rules` 或 Rulesets，把 `pr-security-gate` 设为 required check。
3. 启用 Merge Queue；无法启用时，至少要求分支合并前基于最新 base。
4. 用 CODEOWNERS 负责人审批和 GitHub 合并规则保护契约、账本及入口工作流。

`BLOCK`、模型失败、输出无效、架构规则违规、债务策略违规、审查代码不完整或 SHA 漂移都会使门禁失败。完整步骤、验收用例和 `@v3` → `@v4` 顺序见 [新项目接入说明](../references/new-project-integration.md)。
