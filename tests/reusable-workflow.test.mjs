import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowPath = new URL('../.github/workflows/pr-ai-review.yml', import.meta.url);
const callerTemplatePath = new URL('../templates/project-pr-ai-review.yml', import.meta.url);

test('中心工作流可被项目仓库调用，并声明审查所需 Secret', async () => {
  assert.equal(existsSync(workflowPath), true, '缺少 .github/workflows/pr-ai-review.yml');
  if (!existsSync(workflowPath)) return;

  const yaml = await readFile(workflowPath, 'utf8');
  assert.match(yaml, /workflow_call:/);
  assert.match(yaml, /DEEPSEEK_API_KEY:/);
  assert.match(yaml, /required:\s*true/);
  assert.match(yaml, /repository:\s*li2233-max\/pr-security-gate/);
  assert.match(yaml, /ref:\s*v1/);
  assert.match(yaml, /node \.pr-security-gate\/.github\/scripts\/pr-ai-review\.mjs/);
  assert.doesNotMatch(yaml, /github\.event\.pull_request\.head/);
  assert.doesNotMatch(yaml, /npm (ci|install)|pnpm install|yarn install/);
});

test('项目入口模板只调用中心工作流并显式传递 API Key', async () => {
  assert.equal(existsSync(callerTemplatePath), true, '缺少 templates/project-pr-ai-review.yml');
  if (!existsSync(callerTemplatePath)) return;

  const yaml = await readFile(callerTemplatePath, 'utf8');
  assert.match(yaml, /pull_request:/);
  assert.match(yaml, /uses:\s*li2233-max\/pr-security-gate\/\.github\/workflows\/pr-ai-review\.yml@v1/);
  assert.match(yaml, /DEEPSEEK_API_KEY:\s*\$\{\{ secrets\.DEEPSEEK_API_KEY \}\}/);
  assert.doesNotMatch(yaml, /steps:/);
  assert.doesNotMatch(yaml, /run:/);
});
