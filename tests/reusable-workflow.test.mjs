import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { workflowRunHeadSha } from '../.github/scripts/publish-verification-manifest.mjs';
import { parseTreeEntries } from '../.github/scripts/independent-ci-check.mjs';

const workflowPath = new URL('../.github/workflows/pr-ai-review.yml', import.meta.url);
const verifierWorkflowPath = new URL('../.github/workflows/independent-ci-verification.yml', import.meta.url);
const callerTemplatePath = new URL('../templates/project-pr-ai-review.yml', import.meta.url);
const verifierCallerTemplatePath = new URL('../templates/project-independent-ci-verification.yml', import.meta.url);

test('中心工作流可被项目仓库调用，并声明审查所需 Secret', async () => {
  assert.equal(existsSync(workflowPath), true, '缺少 .github/workflows/pr-ai-review.yml');
  if (!existsSync(workflowPath)) return;

  const yaml = await readFile(workflowPath, 'utf8');
  assert.match(yaml, /workflow_call:/);
  assert.match(yaml, /DEEPSEEK_API_KEY:/);
  assert.match(yaml, /required:\s*true/);
  assert.match(yaml, /actions:\s*read/);
  assert.match(yaml, /checks:\s*read/);
  assert.match(yaml, /security-events:\s*read/);
  assert.match(yaml, /statuses:\s*read/);
  assert.match(yaml, /repository:\s*\$\{\{ job\.workflow_repository \}\}/);
  assert.match(yaml, /ref:\s*\$\{\{ job\.workflow_sha \}\}/);
  assert.match(yaml, /node \.pr-security-gate\/.github\/scripts\/pr-ai-review\.mjs/);
  assert.doesNotMatch(yaml, /github\.event\.pull_request\.head/);
  assert.doesNotMatch(yaml, /npm (ci|install)|pnpm install|yarn install/);
});

test('独立验证工作流只提供固定 workflow_call 入口和固定检查 job', async () => {
  assert.equal(existsSync(verifierWorkflowPath), true, '缺少独立验证 reusable workflow');
  if (!existsSync(verifierWorkflowPath)) return;
  const yaml = await readFile(verifierWorkflowPath, 'utf8');
  assert.match(yaml, /^on:\s*\n\s+workflow_call:\s*$/m);
  assert.doesNotMatch(yaml, /^\s+(?:inputs|secrets):/m);
  assert.match(yaml, /^permissions:\s*\n\s+contents:\s*read\s*\n\s+pull-requests:\s*read\s*$/m);
  for (const check of ['secret-scan', 'sast-config-scan', 'dependency-scan', 'payment-refund-tests', 'authorization-tests', 'production-hardening-tests', 'publish-verification-manifest']) {
    assert.match(yaml, new RegExp(`^  ${check}:$`, 'm'));
  }
  const actionRefs = [...yaml.matchAll(/^\s+-\s+uses:\s*([^\s]+)$/gm)].map(([, value]) => value);
  assert.ok(actionRefs.length >= 2);
  assert.ok(actionRefs.every(value => /@[a-f0-9]{40}$/.test(value)), `workflow has a floating action ref: ${actionRefs.join(', ')}`);
  assert.doesNotMatch(yaml, /secrets:\s*inherit|pull_request_target|npm\s+(?:ci|install)|node\s+miniprogram\//i);
  assert.match(yaml, /node \.verifier\/\.github\/scripts\/independent-ci-check\.mjs/);
  assert.match(yaml, /publish-verification-manifest\.mjs/);
  assert.match(yaml, /name: independent-ci-verification-\$\{\{ github\.run_attempt \}\}/);
});

test('候选仓库不能通过自带 Gitleaks 配置或忽略文件修改中心扫描策略', async () => {
  const runner = await readFile(new URL('../.github/scripts/independent-ci-check.mjs', import.meta.url), 'utf8');
  assert.match(runner, /['"]\.gitleaks\.toml['"]/);
  assert.match(runner, /['"]\.gitleaksignore['"]/);
  assert.match(runner, /'cat-file',\s*'blob'/);
  assert.doesNotMatch(runner, /'archive'/);
});

test('PR 运行的 GitHub head SHA 与候选合并 SHA 分开校验', () => {
  const headSha = 'a'.repeat(40);
  const mergeSha = 'b'.repeat(40);
  assert.equal(workflowRunHeadSha('pull_request', { pull_request: { head: { sha: headSha } } }, mergeSha), headSha);
  assert.equal(workflowRunHeadSha('merge_group', {}, mergeSha), mergeSha);
});

test('候选快照直接读取 Git blob，不执行 archive 属性或链接路径', () => {
  const sha = 'a'.repeat(40);
  assert.deepEqual(parseTreeEntries(Buffer.from(`100644 blob ${sha}\tminiprogram/app.json\0`)), [
    { mode: '100644', sha, path: 'miniprogram/app.json' },
  ]);
  for (const row of [
    `120000 blob ${sha}\tlink\0`,
    `160000 commit ${sha}\tmodule\0`,
    `100644 blob ${sha}\t../outside\0`,
  ]) assert.throws(() => parseTreeEntries(Buffer.from(row)), /candidate/);
});

test('独立验证项目模板只调用固定中心工作流且没有 PR 可控步骤或 Secret', async () => {
  assert.equal(existsSync(verifierCallerTemplatePath), true, '缺少独立验证项目模板');
  if (!existsSync(verifierCallerTemplatePath)) return;
  const yaml = await readFile(verifierCallerTemplatePath, 'utf8');
  assert.match(yaml, /pull_request:/);
  assert.match(yaml, /merge_group:/);
  assert.match(yaml, /checks_requested/);
  assert.match(yaml, /contents:\s*read/);
  assert.match(yaml, /pull-requests:\s*read/);
  assert.match(yaml, /uses:\s*li2233-max\/pr-security-gate\/\.github\/workflows\/independent-ci-verification\.yml@\{\{VERIFIER_SHA\}\}/);
  assert.doesNotMatch(yaml, /steps:|run:|secrets:|inputs:|secrets\s*:\s*inherit/);
});

test('项目入口模板只调用中心工作流并显式传递 API Key', async () => {
  assert.equal(existsSync(callerTemplatePath), true, '缺少 templates/project-pr-ai-review.yml');
  if (!existsSync(callerTemplatePath)) return;

  const yaml = await readFile(callerTemplatePath, 'utf8');
  assert.match(yaml, /pull_request:/);
  assert.match(yaml, /merge_group:/);
  assert.match(yaml, /checks_requested/);
  assert.match(yaml, /actions:\s*read/);
  assert.match(yaml, /checks:\s*read/);
  assert.match(yaml, /security-events:\s*read/);
  assert.match(yaml, /statuses:\s*read/);
  assert.match(yaml, /uses:\s*li2233-max\/pr-security-gate\/\.github\/workflows\/pr-ai-review\.yml@v4/);
  assert.match(yaml, /DEEPSEEK_API_KEY:\s*\$\{\{ secrets\.DEEPSEEK_API_KEY \}\}/);
  assert.doesNotMatch(yaml, /steps:/);
  assert.doesNotMatch(yaml, /run:/);
});
