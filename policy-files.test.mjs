import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const read = (path) => readFile(new URL(`./${path}`, import.meta.url), 'utf8');

test('机器策略定义 AI 审查敏感面与风险等级', async () => {
  const policy = JSON.parse(await read('policy/review-policy.json'));
  assert.ok(policy.sensitiveSurfaces.includes('架构'));
  assert.equal(policy.riskLevels.P0.blocksMerge, true);
  assert.equal(policy.riskLevels.P1.countsAsDebt, true);
  assert.equal(policy.riskLevels.P2.countsAsDebt, true);
});

test('Skill 将安全、架构与累计债务分成独立规则', async () => {
  const skill = await read('SKILL.md');

  assert.match(skill, /securityGate == BLOCK 或 architectureGate == BLOCK/);
  assert.match(skill, /policy\/review-policy\.json/);
  assert.match(skill, /base\/head\/merge SHA/);
  assert.match(skill, /candidateDebt <= baseDebt/);
});

test('Skill 主流程按合并态顺序执行且不允许缺少 base 契约时放行', async () => {
  const skill = await read('SKILL.md');
  const orderedSteps = [
    '审查实际 diff',
    '检查候选合并后的仓库状态',
    '使用受保护 base 版本的架构契约',
    '比较 base 与候选的累计技术债',
    '确认 SHA 仍然有效',
    '输出最终 PASS/BLOCK',
  ];
  let cursor = -1;
  for (const step of orderedSteps) {
    const next = skill.indexOf(step);
    assert.ok(next > cursor, `主流程缺少或顺序错误：${step}`);
    cursor = next;
  }
  assert.doesNotMatch(skill, /兼容放行/);
  assert.match(skill, /PR 描述.*辅助输入/);
});

test('架构契约文档说明候选态、债务棘轮与保守检测边界', async () => {
  const architecture = await read('references/architecture-contract.md');

  assert.match(architecture, /始终使用 base SHA 上的架构契约/);
  assert.match(architecture, /candidateCount <= baseCount/);
  assert.match(architecture, /不是完整跨文件污点分析/);
  assert.match(architecture, /PR A 新增一个 P1/);
});

test('新项目使用 v4 标准入口和 merge_group', async () => {
  const [guide, template, setup] = await Promise.all([
    read('references/new-project-integration.md'),
    read('templates/project-pr-ai-review.yml'),
    read('docs/pr-ai-review-setup.md'),
  ]);

  for (const text of [guide, template, setup]) {
    assert.match(text, /@v4/);
    assert.match(text, /merge_group/);
    assert.match(text, /DEEPSEEK_API_KEY/);
  }
  assert.match(guide, /Branch protection rules/);
  assert.match(guide, /不执行 PR 分支代码/);
  assert.match(template, /types: \[checks_requested\]/);
});

test('README 解释历史债务不会按 PR 清零', async () => {
  const readme = await read('README.md');

  assert.match(readme, /PR A 新增 1 项后显示 1/);
  assert.match(readme, /PR C 没新增则显示 0/);
  assert.match(readme, /真实债务已经是 2/);
  assert.match(readme, /不会自动创建 Git tag/);
});

test('Agent 元数据引导调用 Skill', async () => {
  const agent = await read('agents/openai.yaml');

  assert.match(agent, /PR 安全与架构门禁/);
  assert.match(agent, /\$pr-security-gate/);
  assert.match(agent, /累计技术债/);
});
