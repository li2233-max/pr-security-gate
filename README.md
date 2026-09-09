# PR 安全与架构审查门禁

这是一个可复用的 GitHub Actions 中心仓库。v4 在固定 SHA 上审查安全风险，并用目标仓库 base 分支的架构契约比较候选合并态、累计技术债和必需检查。

主流程固定为：审查实际 diff → 检查合并后的候选仓库 → 按受保护 base 的架构契约判定 → 比较 base/candidate 累计技术债 → 复核 SHA 是否仍有效 → 输出 `PASS/BLOCK`。PR 描述、Checks 和扫描结果只为安全审查提供辅助证据，不能替代合并态、架构契约或债务账本。

最终结论是两个独立门禁的并集：

```text
securityGate == BLOCK 或 architectureGate == BLOCK => BLOCK
```

- 安全 P0 阻断；P1/P2 计入本 PR 技术债。
- 架构新增违规、债务棘轮/预算违规、裁判规则未经审批修改会独立阻断。
- 报告绑定 `base_sha + head_sha/merge_sha`；SHA 漂移时旧结果失效。
- `pull_request` 做单 PR 预审，`merge_group` 在 Merge Queue 的组合候选态重跑。
- base 缺少架构契约或债务账本时直接 `BLOCK`；必须先合入基线文件，再启用 v4 门禁。

## 快速接入

1. 将 [标准入口](templates/project-pr-ai-review.yml) 复制到目标项目 `.github/workflows/pr-ai-review.yml`。它引用 `li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v4`。
2. 从 [架构契约模板](templates/architecture.json) 和 [债务账本模板](templates/debt.json) 开始，按项目定制后先合入受保护 base。
3. 在目标项目配置 `DEEPSEEK_API_KEY`，并把 `pr-security-gate` 加入 Branch protection rules / Rulesets 的 required checks。
4. 启用 GitHub Merge Queue；否则至少要求分支合并前基于最新 base。

标准入口声明 `actions: read`、`checks: read`、`statuses: read` 和 `security-events: read`。可复用工作流不能提升调用方权限，因此不要从目标仓库的入口删除这些权限。

目标仓库不复制中心脚本、Skill 或通用规则。中心流程不会检出、安装或执行 PR 分支代码，只静态读取固定 SHA 的 diff、契约覆盖的源码切片，以及 GitHub 上的 PR 正文、Check Runs 和 Code Scanning 分析/开放告警元数据。所有机器证据必须绑定当前候选 SHA；PR 正文只作为作者声明，不单独证明检查通过。

门禁不会下载完整 Actions 日志、原始 SARIF、artifact，也不会抓取或回显包含 Secret、Token、Cookie、Authorization 等敏感头的 HTTP 请求/响应。Code Scanning API 返回 403/404、没有当前 SHA 的分析、工具或规则数不符合中心策略，或 PR 修改扫描控制路径时会记录为 `unavailable`，而不是伪装成通过；元数据通过不等于已经证明扫描配置和业务覆盖完整。

完整迁移顺序、CODEOWNERS、债务基线和组合测试见 [新项目接入说明](references/new-project-integration.md)。

## “历史债务清零”是什么意思

旧报告只数当前 PR：PR A 新增 1 项后显示 1；PR B 再新增 1 项仍显示 1；PR C 没新增则显示 0，但仓库真实债务已经是 2。v4 用 `.pr-security-gate/debt.json` 保存基线和稳定指纹，报告同时显示“本 PR 新增”和“候选全仓累计”，再按 `ratchet` 或预算策略决定是否阻断。

## 版本

`@v3` 保持原行为。此改造应发布为新的 `v4` tag；合并代码不会自动创建 Git tag，也不会自动修改目标仓库的 Merge Queue、Rulesets 或 CODEOWNERS。
