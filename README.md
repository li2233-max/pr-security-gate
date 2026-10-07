# PR 安全与架构审查门禁

这是一个可复用的 GitHub Actions 中心仓库。v4 在固定 SHA 上审查安全风险，并用目标仓库 base 分支的架构契约比较候选合并态、累计技术债。

主流程固定为：审查实际 diff → 检查合并后的候选仓库 → 按受保护 base 的架构契约判定 → 比较 base/candidate 累计技术债 → 复核 SHA 是否仍有效 → 输出 `PASS/BLOCK`。PR 描述只为 AI 审查提供辅助上下文，不能替代合并态、架构契约或债务账本。

最终结论是两个独立门禁的并集：

```text
securityGate == BLOCK 或 architectureGate == BLOCK => BLOCK
```

- 安全 P0 阻断；P1/P2 计入本 PR 技术债。
- 架构新增违规、债务棘轮/预算违规、候选 PR 试图按放宽后的裁判规则通过会独立阻断。
- 报告绑定 `base_sha + head_sha/merge_sha`；SHA 漂移时旧结果失效。
- `pull_request` 做单 PR 预审，`merge_group` 在 Merge Queue 的组合候选态重跑。
- base 缺少架构契约或债务账本时直接 `BLOCK`；必须先合入基线文件，再启用 v4 门禁。

## 快速接入

1. 将 [标准入口](templates/project-pr-ai-review.yml) 复制到目标项目 `.github/workflows/pr-ai-review.yml`。它引用 `li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v4`。
2. 从 [架构契约模板](templates/architecture.json) 和 [债务账本模板](templates/debt.json) 开始，按项目定制后先合入受保护 base。
3. 在目标项目配置 `DEEPSEEK_API_KEY`，并把 `pr-security-gate` 加入 Branch protection rules / Rulesets 的 required checks。
4. 启用 GitHub Merge Queue；否则至少要求分支合并前基于最新 base。

**AI 审查**：看 PR 改了什么，以及候选合并后的代码，判断可能的上线风险。独立 CI 验证已移除；密钥扫描、依赖漏洞审计和生产配置检查不再作为独立流程或前置门禁。AI 仍会分析源码中的凭据泄露、依赖使用和配置风险。

标准入口只需 `contents: read` 和 `pull-requests: write`，用于读取固定 SHA 的代码、契约和债务账本，以及发布 PR 评论。中心流程读取 PR 描述、完整可审查 diff、契约覆盖的源码与变更文件，并将候选合并态传给 AI。报告绑定当前 SHA，发布前再次复核。

不安装项目依赖、不执行 PR 代码、不采集 GitHub Check Runs、legacy statuses 或 Code Scanning 结果。测试、扫描结果缺失本身不阻断；实际 P0、源码不完整、模型失败、架构或累计债务违规仍会 `BLOCK`。契约和账本的负责人审批由目标项目的 CODEOWNERS 和 GitHub 合并规则执行。

完整迁移顺序、CODEOWNERS、债务基线和组合测试见 [新项目接入说明](references/new-project-integration.md)。

## “历史债务清零”是什么意思

旧报告只数当前 PR：PR A 新增 1 项后显示 1；PR B 再新增 1 项仍显示 1；PR C 没新增则显示 0，但仓库真实债务已经是 2。v4 用 `.pr-security-gate/debt.json` 保存基线和稳定指纹，报告同时显示“本 PR 新增”和“候选全仓累计”，再按 `ratchet` 或预算策略决定是否阻断。

## 版本

`@v3` 保持原行为。此改造应发布为新的 `v4` tag；合并代码不会自动创建 Git tag，也不会自动修改目标仓库的 Merge Queue、Rulesets 或 CODEOWNERS。
