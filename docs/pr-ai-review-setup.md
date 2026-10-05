# 项目接入 PR 安全与架构门禁

`li2233-max/pr-security-gate` 是中心规则仓库。目标项目只保留标准入口，以及属于该项目的 `.pr-security-gate/architecture.json` 和 `.pr-security-gate/debt.json`。

## 标准入口

当 PR 需要修改项目自己的 CI 工作流时，额外的可信验证入口与威胁模型见 [Independent CI verifier](independent-ci-verifier.md)。普通 Actions 检查仍按现有规则处理，不会因为同名或重跑而自动变可信。

把 [项目入口模板](../templates/project-pr-ai-review.yml) 复制为目标项目的 `.github/workflows/pr-ai-review.yml`。它引用：

```text
li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v4
```

入口同时监听 `pull_request` 与 `merge_group` 的 `checks_requested`，后者用于 GitHub Merge Queue。目标项目必须显式映射 `DEEPSEEK_API_KEY`，不要使用 `secrets: inherit`。

入口的 `permissions` 是证据采集契约的一部分：

- `contents: read`：读取固定 SHA 的 diff、契约和候选源码切片。
- `checks: read`、`statuses: read`：读取当前候选 SHA 的 Check Runs 和 legacy commit statuses。
- `actions: read`：核验 GitHub Actions Check 所属 workflow run 及其 workflow 来源。
- `security-events: read`：读取 Code Scanning analysis 与开放 alert 的元数据。
- `pull-requests: write`：读取 PR 状态并发布或更新审查评论。

GitHub 对可复用工作流采用权限收窄规则：被调用工作流不能把调用方未授予的权限提升回来。因此，必须在目标仓库入口保留模板中的权限；只修改中心 workflow 不足以让证据 API 可用。

## 证据采集边界

门禁读取 PR 正文、Check Runs、commit statuses 和 Code Scanning 元数据，并把证据绑定到当前 candidate SHA。PR 正文中的测试名、结果和链接仅是作者声明；即使正文写着“PASS”或“401/403 已验证”，也不能单独满足必需证据。GitHub Actions Check 还要绑定 Check Suite 与成功的 workflow run，并证明顶层 workflow 在 base 与候选间未改变；legacy status 不参与机器通过判定或架构审批。

已发现的 pending Check 或尚未生成当前 SHA analysis 的 Code Scanning 会有界等待并重采集，默认上限 180 秒；超时、API 返回 403/404 或证据无法绑定候选 SHA 时，状态记为 `unavailable`/缺失，不会当作通过。Code Scanning 还必须使用中心策略允许的工具、达到最低规则数，并且 PR 未修改扫描控制路径；这些元数据校验仍不能证明扫描配置覆盖充分，高风险改动应使用受保护的扫描资产或人工复核。门禁不下载完整 Actions 日志、原始 SARIF 或 artifact，也不抓取 PR/Check 链接指向的外部内容；请勿在 PR 正文中粘贴 Secret、Token、Cookie、Authorization header 或完整 HTTP 请求/响应。

## 项目架构契约

### 检查全绿但证据仍显示未验证

当前信任策略会拒绝在同一个 PR 中修改 `.github/workflows/` 或 `.github/actions/` 后产生的 Actions 证据，包括只升级中心工作流版本的变更。测试运行成功不等于来源校验成功，重新运行同一 PR 也不会改变这一点。

应把 CI 入口升级和测试范围调整放在独立的配置 PR 中，先按仓库已有的独立审批流程审核并建立 base 基线，再把新的 base 合入业务分支。业务 PR 相对 base 不再修改 CI 控制文件后，才可使用该基线工作流产生的检查作为证据。若当前保护规则没有配置变更的独立审批路径，应由仓库负责人决定治理方式；不要删除必需检查或临时放宽证据信任规则。

AI 调用前会收到固定 SHA 上的架构预检结果，包括配置状态、违规增量和债务数量，避免把已经读取的契约/账本误写成“未提供”。AI 返回后仍会把本次新发现的 P1/P2 加入同一快照重新核对债务；最终 PASS/BLOCK 继续由安全与架构两个门禁共同决定。

先按项目实际情况定制并合入 base：

- [架构模板](../templates/architecture.json) → `.pr-security-gate/architecture.json`
- [债务模板](../templates/debt.json) → `.pr-security-gate/debt.json`

不要原样保留模板中的占位检查名。契约修改使用 base 版本规则评估，并要求真实存在的负责人检查；债务账本应从当前真实基线开始，不能把历史问题清零。

v4 不提供“未配置兼容放行”：受保护 base 缺少任一基线文件都会 `BLOCK`。因此必须先通过旧门禁或人工审批把契约与债务基线合入 base，再把项目入口升级到 `@v4`。

## GitHub 设置

1. 在 `Settings → Secrets and variables → Actions → Secrets` 新建 `DEEPSEEK_API_KEY`。
2. 先运行一次门禁，再到 `Settings → Branches → Branch protection rules` 或 Rulesets，把 `pr-security-gate` 设为 required check。
3. 启用 Merge Queue；无法启用时，至少要求分支合并前基于最新 base。
4. 用 CODEOWNERS 和独立审批检查保护契约、账本及入口工作流。

`BLOCK`、模型失败、输出无效、架构规则违规、债务策略违规、必需检查缺失或 SHA 漂移都会使门禁失败。完整步骤、验收用例和 `@v3` → `@v4` 顺序见 [新项目接入说明](../references/new-project-integration.md)。
