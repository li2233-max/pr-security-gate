import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

for (const file of [
  'SKILL.md',
  'references/review-output.md',
  'references/evidence-requirements.md',
]) {
  test(`审查基线包含 ${file}`, async () => {
    const text = await readFile(new URL(`./${file}`, import.meta.url), 'utf8');
    assert.ok(text.includes('P0'));
  });
}

test('证据规则按敏感面分流，CI 改动不套用接口鉴权证据', async () => {
  const [skill, evidence, output] = await Promise.all([
    readFile(new URL('./SKILL.md', import.meta.url), 'utf8'),
    readFile(new URL('./references/evidence-requirements.md', import.meta.url), 'utf8'),
    readFile(new URL('./references/review-output.md', import.meta.url), 'utf8'),
  ]);

  assert.match(skill, /仅 CI、配置或依赖改动/);
  assert.match(skill, /中心模板中的 `pull_request` 入口本身不作为 P0\/P1\/P2 风险或技术债/);
  assert.match(evidence, /不得因仅 CI、配置或依赖改动而要求 401\/403/);
  assert.match(evidence, /标准 `pull_request` 入口本身不构成风险项/);
  assert.match(output, /必须指明缺失证据对应的敏感面/);
});

test('新项目接入说明提供中心工作流、Secret、验证和分支保护步骤', async () => {
  const [skill, guide] = await Promise.all([
    readFile(new URL('./SKILL.md', import.meta.url), 'utf8'),
    readFile(new URL('./references/new-project-integration.md', import.meta.url), 'utf8'),
  ]);

  assert.match(skill, /references\/new-project-integration\.md/);
  assert.match(guide, /\.github\/workflows\/pr-ai-review\.yml/);
  assert.match(guide, /li2233-max\/pr-security-gate\/\.github\/workflows\/pr-ai-review\.yml@v2/);
  assert.match(guide, /DEEPSEEK_API_KEY/);
  assert.match(guide, /pull_request/);
  assert.match(guide, /Branch protection rules/);
  assert.match(guide, /不复制审查脚本或规则文件/);
});

test('README 说明中心仓库用途与 v2 接入方式', async () => {
  const readme = await readFile(new URL('./README.md', import.meta.url), 'utf8');

  assert.match(readme, /PR 安全审查门禁/);
  assert.match(readme, /li2233-max\/pr-security-gate\/\.github\/workflows\/pr-ai-review\.yml@v2/);
  assert.match(readme, /DEEPSEEK_API_KEY/);
  assert.match(readme, /Branch protection rules/);
  assert.match(readme, /new-project-integration\.md/);
});
