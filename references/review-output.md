# PR Code Review 固定输出模板

未知元数据写“未提供”；未运行的测试、扫描或请求/响应必须写“未提供”。报告第一个非空行必须是 `Code Review 完成`，随后可放隐藏评论标记。

```markdown
Code Review 完成
<!-- pr-security-gate-report -->
仓库：<owner/repository>
分支：<分支名>
提交：<PR head 或 merge-group SHA>
提交信息：<提交信息>
提交者：<提交者>
Review 模式：<incremental / merge-group / full>
事件：<pull_request / merge_group>
目标 Base SHA：<实际目标分支 base SHA>
PR Head SHA：<PR head；merge_group 时为组合 SHA>
候选 Merge SHA：<实际审查的候选 SHA>
队列 Parent SHA：<merge_group payload base SHA；不适用则“不适用”>

安全门禁：BLOCK / PASS
架构门禁：BLOCK / PASS / 未配置（BLOCK）
判定结果：BLOCK / PASS
合并动作：禁止合并 / 可合并
结论依据：<分别说明安全与架构结论的可观察依据>

审查范围：
- 本次范围：<diff、候选合并态及受影响架构切片>
- 未审查范围：<测试、扫描、运行时配置、未被契约覆盖路径等；无则“无”>

审查摘要：
<1—3 句概括改动、关键风险和结论>

值得肯定：
- <有证据支持的正确设计、修复或测试；无则“无”>

变更的敏感面：
- 接口：涉及 / 未涉及 / 无法判断；<理由>
- 认证：涉及 / 未涉及 / 无法判断；<理由>
- 鉴权：涉及 / 未涉及 / 无法判断；<理由>
- 权限：涉及 / 未涉及 / 无法判断；<理由>
- 数据：涉及 / 未涉及 / 无法判断；<理由>
- 文件：涉及 / 未涉及 / 无法判断；<理由>
- 配置：涉及 / 未涉及 / 无法判断；<理由>
- 依赖：涉及 / 未涉及 / 无法判断；<理由>
- CI：涉及 / 未涉及 / 无法判断；<理由>
- 架构：涉及 / 未涉及 / 无法判断；<理由>

需关注的问题：
- [P0/P1/P2] [HIGH/MEDIUM/LOW] <标题>
  - 规则：<稳定 ruleId>
  - 技术债指纹：<P1/P2 使用；P0 不适用>
  - 位置：<文件:行号或范围>
  - 类型：安全 / 正确性 / 可用性 / 数据完整性 / 可观测性 / 可维护性
  - 依据或变更前后行为：<可观察 diff 或证据>
  - 攻击路径或失败路径：<如何触发>
  - 影响范围：<账户、租户、数据、系统、审计或业务>
  - 修复建议：<可执行修复和验证>
  - 是否阻塞安全门禁：<P0 是；P1/P2 否>
  - 状态：未解决 / 已缓解
- 无：<无问题时填写；否则不得填写“无”>

架构门禁详情：
- 配置状态：已配置 / 未配置
- 新增违规：<ruleId、路径、base→candidate 行为；无则“无”>
- 已有违规：<保持不变且不阻断的遗留项；无则“无”>
- 已消除违规：<候选态不再出现的项；无则“无”>

本 PR 技术债：<当前 diff 的 P1/P2 数量> 项
累计技术债：
- 模式：ratchet / budget / 未启用
- 基线 → 候选：<N → M>
- 各组件基线 → 候选：<component: N → M>
- 本次登记：<N；逐项含 level、component、path、ruleId、fingerprint、firstSeen>
- 已有：<N；逐项含同上字段>
- 声明已解决、待证据复核：<N；逐项含同上字段>
- 本次发现但未登记：<N；逐项给出应登记的稳定指纹>
- 本次登记等级不一致：<N；例如模型判定 P1 而账本写成 P2>
- 已逾期：<N；逐项显示 firstSeen 和指纹>
- 首次出现时间无效：<N；future firstSeen 必须阻断>
```

## 结论校验

| securityGate | architectureGate | 最终结果 |
| --- | --- | --- |
| `BLOCK` | 任意 | `BLOCK` |
| `PASS` | `BLOCK` | `BLOCK` |
| `PASS` | `PASS` | `PASS` |
| `PASS` | 未配置 | `BLOCK`，受保护 base 必须先配置架构契约和债务账本 |

`securityGate=BLOCK` 的条件包括 P0、审查代码不完整、无实际 diff、模型失败或输出无效。`architectureGate=BLOCK` 的条件包括 base 契约或债务账本缺失、候选删除契约、新增架构违规、债务未登记、严格 ratchet 或预算越界。P1/P2 本身不使安全门禁失败，但会参与累计债务比较。SHA 在审查期间变化时不得发布旧报告。

`merge_group` 没有单一 PR 评论位置；报告写入 GitHub Actions job summary，由组合候选 SHA 上的必需检查给出最终门禁结果。
