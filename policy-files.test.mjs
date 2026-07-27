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
  assert.match(evidence, /不得因仅 CI、配置或依赖改动而要求 401\/403/);
  assert.match(output, /必须指明缺失证据对应的敏感面/);
});
