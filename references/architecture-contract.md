# 架构契约与累计技术债

## 作用与信任边界

目标仓库可在受保护 base 分支保存：

- `.pr-security-gate/architecture.json`：架构不变量和债务策略；从 [模板](../templates/architecture.json) 开始定制。
- `.pr-security-gate/debt.json`：全仓尚未关闭的 P1/P2 台账；格式见 [模板](../templates/debt.json)。

门禁始终使用 base SHA 上的架构契约评估候选合并态。候选 PR 修改契约不会在同一次审查中放宽规则；修改必须通过 base 契约的 `contractChangeCheck`。该名称必须对应目标项目真实存在的 Check Run，且其 candidate SHA、Check Suite、workflow run 与未变 base workflow 来源均通过校验；同名 legacy status 或 PR 自建工作流不能冒充审批。再用 CODEOWNERS 保护架构契约、债务账本和入口工作流。

```text
/.pr-security-gate/architecture.json  @architecture-team
/.pr-security-gate/debt.json          @architecture-team
/.github/workflows/pr-ai-review.yml   @security-team
```

若受保护 base 没有架构契约或债务账本，`architectureGate=BLOCK`。首次接入不能由同一个候选 PR 一边创建裁判规则一边按自己的规则通过；应先在旧门禁或人工架构审批下把契约和真实债务基线合入 base，再启用 v4。

## 可确定执行的规则

契约模板是字段的唯一示例，核心能力包括：

- `components`：文件路径所属组件、识别该组件引用的 marker，以及允许依赖的组件。
- `resourceRules`：Secret、数据库或消息总线等关键资源只能在哪些组件引用。
- `combinationRules`：候选切片出现敏感源与外部输出 marker 的新组合时保守阻断。例如已有 Secret 读取，另一 PR 新增 Webhook 后，组合态会被识别。
- `criticalPaths`：认证、租户、支付、迁移或契约文件变化时必须成功的目标项目检查。
- `contractChangeCheck`：允许修改契约前必须成功的独立审批检查。
- `debtBudgets`：`ratchet` 或 `budget` 债务策略和全仓/组件额度。

用户提出的核心不变量可按下表落地；模板里的路径和检查名只是示例，必须换成目标项目真实值：

| 不变量 | 确定性落点 |
| --- | --- |
| 模块依赖方向、禁止跨层调用 | `components.allowedDependencies` + `referenceMarkers` |
| 私有接口必须经过认证层 | 认证路径的 `criticalPaths.requiredChecks` |
| 租户归属来自服务端身份上下文 | 租户路径的独立隔离测试 check |
| 核心写入具备事务、唯一约束或幂等键 | 写入/迁移路径的事务与并发测试 check |
| Secret 只能进入适配层 | `resourceRules` |
| 外部网络和部署暴露边界 | `combinationRules` + 部署路径 check |
| 各组件技术债预算 | `debtBudgets` 与债务账本 |

这些检查只静态读取文本，不安装依赖、不加载项目配置、不执行 PR 代码。`referenceMarkers` 和组合规则必须按项目真实导入路径、API 和框架定制。

`combinationRules` 是保守共现检测，不是完整跨文件污点分析。它能发现“候选态新增 Secret + Webhook/HTTP 输出组合”，但不能证明具体值必然流入 payload；命中后应补充 SAST、数据流分析或人工复核。未命中也不能证明不存在复杂间接数据流。

## 候选态与受影响切片

`pull_request` 使用固定 base SHA 与候选 merge SHA；`merge_group` 从目标 `base_ref` 读取当前 tip，并与队列组合候选 SHA 比较。工作流读取契约覆盖的文件，构建 base/candidate 依赖图并只阻断新增违规。历史已有循环或非法边保持不变时不会误伤无关 PR；删除违规边会记录为已消除。

源码切片有文件数、单文件和总字节上限。树被截断、契约无效或切片超过上限时 fail closed。完整业务调用图、运行时配置和未被契约覆盖的路径仍属于未审查范围。

## 累计技术债

旧报告中的 `technicalDebtCount` 只表示当前 PR 的 P1/P2 数量。例如：

```text
main 初始债务：0
PR A 新增一个 P1：报告 1；合并后真实累计 1
PR B 新增一个 P2：旧报告仍写 1；真实累计已是 2
PR C 没有新问题：旧报告写 0；但 A、B 的两项仍存在
```

这就是“每个 PR 只统计自己、历史看起来清零”。新版用债务账本保存累计状态，并为每项计算：

```text
canonical = JSON.stringify([lower(ruleId), lower(component), normalizedPath])
fingerprint = sha256(canonical)
候选累计 = base 已有 + 本次登记 - 声明解决
```

`normalizedPath` 统一 `/` 分隔符但保留 Git 路径大小写，并拒绝绝对路径和 `..`；因此 Linux 仓库中的 `Auth.js` 与 `auth.js` 不会碰撞。

账本条目至少包含 `fingerprint`、`ruleId`、`component`、`path`、`level` 和不可回写的 `firstSeen`。本 PR 的 P1/P2 未出现在候选账本时，架构门禁阻断并在报告中给出所需指纹。

### `ratchet`

严格执行 `candidateCount <= baseCount`。已有债务不变或下降可以通过；任何净增长都阻断。模板默认使用此模式。

### `budget`

base 未超预算时，候选可增长到预算；首次超过预算阻断。base 已经超预算时，不变或下降可以通过，继续增长阻断。这避免历史遗留问题锁死所有无关开发。

`debtBudgets.maxAgeDays` 可限制债务存活时间。未配置时不检查年龄；配置后，`firstSeen` 超龄的未关闭条目会阻断，即使本 PR 没有增加数量。模板示例为 90 天，接入时应改成团队真实 SLA。

从候选账本删除条目只表示“声明已解决”，不自动证明代码已经修复。契约应把债务文件列为关键路径，并要求修复测试、扫描结果及负责人审批。

## 接入要求

1. 先在 base 合入按项目定制的契约、当前真实债务基线和 CODEOWNERS。
2. 将 `contractChangeCheck` 和 `criticalPaths.requiredChecks` 改为项目真实存在的检查名称。
3. 再升级入口到 `@v4` 并启用 Merge Queue，或至少要求分支基于最新 base。
4. 用一个组合测试验证：PR A 和 PR B 对旧 base 单独成立，但队列候选 A+B 违反依赖或组合规则时必须 `BLOCK`。
