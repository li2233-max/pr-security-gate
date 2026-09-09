import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { normalizeEvidenceRecord, validateEvidencePolicy } from './.github/scripts/evidence.mjs';

const read = (path) => readFile(new URL(`./${path}`, import.meta.url), 'utf8');

test('机器策略是安全敏感面与等级映射的事实源', async () => {
  const policy = JSON.parse(await read('policy/review-policy.json'));

  assert.equal(policy.schemaVersion, 2);
  assert.ok(Object.hasOwn(policy.evidencePolicy.requirementsBySurface, '架构'));
  assert.equal(policy.riskRules['tenant-isolation.violation'].includes('租户'), true);
  assert.equal(policy.riskLevels.P0.severity, 'HIGH');
  assert.equal(policy.riskLevels.P0.blocksMerge, true);
  assert.equal(policy.riskLevels.P1.countsAsDebt, true);
  assert.equal(policy.riskLevels.P2.countsAsDebt, true);
  assert.deepEqual(policy.evidencePolicy.requirementsBySurface.权限.anyOf, ['authorization_test', 'http_exchange']);
  assert.equal(policy.evidencePolicy.sources.pr_assertion.verified, false);
  assert.deepEqual(policy.evidencePolicy.codeScanning.trustedTools, ['CodeQL']);
  assert.equal(policy.evidencePolicy.codeScanning.minimumRules, 1);
});

test('安全证据要求只从机器策略读取', async () => {
  const [script, evidenceRequirements] = await Promise.all([
    read('.github/scripts/pr-ai-review.mjs'),
    read('references/evidence-requirements.md'),
  ]);

  assert.doesNotMatch(script, /requiresAccessControlEvidence|hasAccessControlEvidence/);
  assert.match(script, /Object\.keys\(EVIDENCE_POLICY\.requirementsBySurface\)/);
  assert.match(evidenceRequirements, /硬门禁.*policy\/review-policy\.json/);
});

test('证据策略拒绝可导致 fail-open 的配置', async () => {
  const reviewPolicy = JSON.parse(await read('policy/review-policy.json'));
  const valid = reviewPolicy.evidencePolicy;
  assert.equal(validateEvidencePolicy(valid), valid);

  const emptyRequirement = structuredClone(valid);
  emptyRequirement.requirementsBySurface.权限.anyOf = [];
  assert.throws(() => validateEvidencePolicy(emptyRequirement), /anyOf 不能为空/);

  const failedMeansPassing = structuredClone(valid);
  failedMeansPassing.passingStatuses = ['failed'];
  assert.throws(() => validateEvidencePolicy(failedMeansPassing), /只能是/);

  const unknownType = structuredClone(valid);
  unknownType.checkClassifiers[0].type = 'unknown_type';
  assert.throws(() => validateEvidencePolicy(unknownType), /未知证据类型/);

  const invalidRegex = structuredClone(valid);
  invalidRegex.checkClassifiers[0].pattern = '[';
  assert.throws(() => validateEvidencePolicy(invalidRegex), /有效正则表达式/);

  const trustedAuthorClaim = structuredClone(valid);
  trustedAuthorClaim.sources.pr_assertion.verified = true;
  assert.throws(() => validateEvidencePolicy(trustedAuthorClaim), /pr_assertion\.verified 必须是 false/);

  const emptyTrustedScanners = structuredClone(valid);
  emptyTrustedScanners.codeScanning.trustedTools = [];
  assert.throws(() => validateEvidencePolicy(emptyTrustedScanners), /trustedTools 必须是非空数组/);

  const invalidScanningPattern = structuredClone(valid);
  invalidScanningPattern.codeScanning.controlPathPatterns = ['['];
  assert.throws(() => validateEvidencePolicy(invalidScanningPattern), /有效正则表达式/);

  assert.throws(() => normalizeEvidenceRecord({
    type: 'authorization_test',
    source: 'code_scanning_analysis',
    status: 'passed',
    sha: 'merge1234',
    url: 'https://github.com/owner/repo/security/code-scanning',
    name: '伪造授权分析',
    summary: '错误地复用 Code Scanning 来源。',
    producer: 'evil',
  }, { candidateSha: 'merge1234', policy: valid }), /type 与 source 不匹配/);

  assert.throws(() => normalizeEvidenceRecord({
    type: 'toString',
    source: 'system',
    status: 'passed',
    sha: 'merge1234',
    url: 'https://github.com/owner/repo/commit/merge1234',
    name: '原型键',
    summary: '不得借用对象原型属性。',
  }, { candidateSha: 'merge1234', policy: valid }), /type 不在机器策略中/);

  assert.throws(() => normalizeEvidenceRecord({
    type: 'author_claim',
    source: 'toString',
    status: 'claimed',
    sha: 'merge1234',
    url: 'https://github.com/owner/repo/pull/1',
    name: '原型来源',
    summary: '不得借用对象原型属性。',
  }, { candidateSha: 'merge1234', policy: valid }), /source 不在机器策略中/);
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
  assert.match(skill, /证据.*辅助输入/);
});

test('证据规则区分敏感面证据与架构确定性证据', async () => {
  const [evidence, output] = await Promise.all([
    read('references/evidence-requirements.md'),
    read('references/review-output.md'),
  ]);

  assert.match(evidence, /“未提供 401\/403”只是缺证声明/);
  assert.match(evidence, /依赖边、依赖环、资源规则、命名检查和债务预算/);
  assert.match(evidence, /base_sha \+ queue_parent_sha \+ merge_sha/);
  assert.match(evidence, /fail closed/);
  assert.match(evidence, /扫描配置.*不能.*证明/);
  assert.match(output, /未验证、失败或不可用证据/);
  assert.match(output, /未验证声明（不参与门禁）/);
  assert.match(output, /证据缺口/);
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
