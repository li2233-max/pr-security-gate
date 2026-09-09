# 可验证证据要求

## 通用规则

证据必须让 PR 审查者能够复现或直接检查，例如带结果的测试名称、扫描报告、关键 HTTP 请求/响应、固定 SHA 上的 diff，以及已核验的风险接受记录。作者声明、模型推断、计划运行的检查和旧 PR 评论都不是证据；没有材料时写“未提供”。

每份结论必须绑定以下身份：

- `pull_request`：`base_sha + head_sha + merge_sha`。
- `merge_group`：目标分支当前 `base_sha + queue_parent_sha + merge_sha`。

这些 SHA 在审查期间发生变化时，当前结果已过期，必须停止发布并在新候选态重跑。

## 自动采集来源与信任边界

门禁自动读取 PR 正文、Check Runs、legacy commit statuses，以及 Code Scanning analysis/开放 alert 元数据。证据记录使用结构化字段 `type/source/status/sha/url`，只有来源受信、状态通过且 `sha` 与当前 candidate SHA 完全一致的记录才能满足必需证据。

PR 正文属于 `pr_assertion`：它可以说明作者运行了什么并提供 Check 链接，但只是声明，不能单独证明结果。Legacy commit status 同样不自动升级为可信机器证据，也不能满足架构审批。GitHub Actions Check 还必须同时绑定当前候选 SHA、对应 Check Suite、成功的 workflow run，以及 base 已定义且候选未篡改的顶层 workflow；只要 PR 修改 `.github/workflows/` 或 `.github/actions/` 下的执行控制文件，本次 Actions Check 就不会升级为可信证据。仅凭 Check 名称、链接或 `github-actions` 应用身份不够。该校验仍不证明 PR 未修改普通测试代码或 package script，因此高风险检查应使用受保护的测试资产和人工复核。

当已发现的可信 Check 仍为 pending，或 Code Scanning 尚未生成当前 SHA 的 analysis 时，门禁会在最多 180 秒的有界窗口内重采集；超时后仍按缺失或 `unavailable` fail closed。证据超过 100 项时停止自动判定，避免模型上下文和 GitHub 评论被无界输入撑满。

Code Scanning 只读取 analysis 和开放 alert 的元数据，不下载原始 SARIF。analysis 必须使用 `policy/review-policy.json` 允许的工具、达到最低规则数，并且本 PR 没有修改策略列出的扫描控制路径；否则记录 `unavailable`。API 返回 403/404、在等待窗口后仍没有当前 SHA 的 analysis，或 SHA 无法核对时，同样不能当成零告警或扫描通过。这里的“已验证”只表示来源、状态和 SHA 通过了机器校验；扫描配置没有被弱化、规则覆盖充分以及业务安全性，不能只由 analysis 元数据证明，高风险改动仍需受保护的扫描资产或人工复核。

门禁不下载完整 Actions 日志或 artifact，也不访问 PR/Check 链接来抓取外部 HTTP 请求/响应。报告只保留经过截断和脱敏的摘要及 GitHub 链接；任何 Secret、Token、Cookie、Authorization header 或完整敏感 HTTP 内容都不应进入 PR 正文或 Check 摘要。

风险定级同时考虑影响范围、可利用性、暴露范围和运行时可达性。扫描器标签与 CVSS 不是最终结论；依赖告警还应结合 EPSS、KEV、直接/间接依赖和生产可达性。

## 按敏感面检查

| 敏感面 | 检查重点 | 最低可验证证据 |
| --- | --- | --- |
| 接口、认证 | 私有端点、登录、Token、会话、失效与撤销 | 未登录请求得到 401/403；失效 Token 无法继续使用 |
| 鉴权、权限、数据 | 服务端角色校验、对象归属、租户边界、管理员操作 | 普通用户不能访问管理员资源；用户 A 不能读写用户 B 数据；租户归属来自服务端身份上下文 |
| 支付、后台、核心写入 | 金额或状态变更、幂等、事务、唯一约束、批量导出 | 权限拒绝与资源归属测试；重复请求、并发写入及失败回滚证据 |
| 文件 | 类型、大小、内容、路径遍历、上传/下载授权 | 非法类型或路径被拒绝；上传/下载具备认证和归属校验 |
| 输入处理 | SQL/命令/模板注入、SSRF、反序列化、外部回调 | 参数化 API 的 diff 证据；危险输入被拒绝的测试；回调签名或来源校验 |
| Secret、日志 | 密钥、Token、私钥、`.env`、个人数据、调试日志 | Secret 扫描；日志或错误响应不含敏感值；疑似泄露时完成吊销或轮换 |
| 配置、部署 | CORS、Cookie、安全头、调试模式、容器、IaC、网络暴露 | 候选配置 diff；相关 IaC、镜像或配置扫描结果 |
| 依赖 | 新增或升级依赖、锁文件、漏洞公告 | CVSS、EPSS、KEV、作用范围和运行时可达性；仅开发依赖或不可达必须有可复核依据 |
| CI | 扫描跳过、Secret 权限、第三方 Action、部署条件 | 工作流 diff；Secret、静态、依赖及适用的镜像/IaC 扫描结果 |
| 架构 | 禁止依赖、依赖环、关键资源边界、关键路径、债务预算 | base 契约、base/candidate 图与违规集合、命名检查结果、债务账本前后对比 |

仅 CI、配置或依赖改动时，不得机械要求 401/403、用户 A/B 或失效 Token 证据。反过来，认证、权限、对象归属或租户隔离发生变化时，缺少对应授权证据必须 `BLOCK`。“未提供 401/403”只是缺证声明，不是已经验证。机器策略中的路径分类器提供最低敏感面，模型可以增加命中项，但不能把机器命中的路径降级为“未涉及”。

标准 `pull_request` 和 `merge_group` 入口本身不构成 P0/P1/P2；应审查的是它们的权限、触发范围和候选状态处理。

## 外部 API、批处理和错误语义

外部 API 或批处理变化应覆盖边界批次、部分失败、全部失败、重试/超时/幂等，以及调用方如何区分业务空结果与系统失败。把异常改为 `{}`、`[]`、`None`、`False` 或空字符串时，必须验证调用方不会把失败当作正常结果。

若错误会影响权限、租户隔离、核心数据、资金或审计可见性，按安全 P0 处理；普通可靠性或架构退化保持在独立的架构门禁中。

## 架构证据边界

确定性门禁负责依赖边、依赖环、资源规则、命名检查和债务预算。AI 只解释这些结果，不得覆盖硬规则。

`combinationRules` 的源/汇 marker 共现是保守预警，不是完整污点分析。命中时应补 SAST、数据流分析或人工复核；未命中也不能证明复杂间接数据流安全。

修改 `.pr-security-gate/architecture.json` 或删除债务账本条目时，必须提供 base 契约要求的独立检查。CODEOWNERS 可以要求负责人评审，但只有通过上述 candidate SHA、Check Suite、workflow run 与未变 base workflow 来源校验的 Check Run，才能满足 `contractChangeCheck` 或 `criticalPaths.requiredChecks`；同名 legacy status 不算审批。

## 最低 CI 证据

按改动范围提供适用的 Secret、静态安全、依赖漏洞、镜像或 IaC 扫描。哪些敏感面需要哪一种或哪一组证据、证据之间是替代关系还是共同要求，硬门禁只读取 `policy/review-policy.json`，本文不另建一套映射。静态扫描不能证明业务越权安全；涉及接口或数据访问时，还需策略要求的授权回归证据和必要的人工安全复核。

模型失败、扫描失败或跳过、契约无效、受影响切片超限、必需检查缺失，以及 SHA 漂移都应 fail closed。
