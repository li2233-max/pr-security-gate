import assert from 'node:assert/strict';
import test from 'node:test';
import { createWorkflowDependencies, runReview, validateReview } from '../.github/scripts/pr-ai-review.mjs';

const surfaces = Object.fromEntries(['接口', '认证', '鉴权', '权限', '数据', '文件', '配置', '依赖', 'CI', '架构']
  .map(name => [name, { status: '涉及', reason: '本次变更涉及此范围' }]));
const review = () => ({ conclusion: 'PASS', summary: '根据候选源码未发现上线风险', positives: [], sensitiveSurfaces: surfaces, risks: [], technicalDebtCount: 0 });
const inputs = {
  contract: { version: 1, components: [{ name: 'app', paths: ['src/**'], referenceMarkers: ['@app/'], allowedDependencies: [] }], resourceRules: [], criticalPaths: [], debtBudgets: { mode: 'ratchet', total: 0, components: { app: 0 } } },
  baseFiles: [{ path: 'src/app.js', content: 'export const enabled = false;' }],
  candidateFiles: [{ path: 'src/app.js', content: 'export const enabled = true; // candidate-context-marker' }],
  baseDebt: { version: 1, items: [] }, candidateDebt: { version: 1, items: [] },
};

test('敏感面涉及时可根据 AI 代码审查通过，无须独立 CI 或扫描结果', () => {
  assert.equal(validateReview(review(), { changedFiles: ['src/auth/login.js', 'package.json', 'deploy/prod.yml'] }).conclusion, 'PASS');
});

test('AI 收到候选合并后的源码，审查流程不读取独立 CI 证据', async () => {
  let prompt;
  const result = await runReview({
    getPullRequest: async () => ({ repository: 'owner/repo', baseSha: 'base', headSha: 'head', mergeSha: 'candidate', isFork: false }),
    getDiff: async () => 'diff --git a/src/app.js b/src/app.js\n@@ -1 +1 @@\n-old\n+new',
    getEvidence: async () => { throw new Error('不得读取 CI 证据'); },
    getArchitectureInputs: async () => structuredClone(inputs),
    readPolicy: async () => 'AI 审查规则',
    callModel: async request => { prompt = request.prompt; return review(); },
    upsertComment: async () => {},
  });
  assert.equal(result.conclusion, 'PASS');
  assert.ok(prompt.includes('candidate-context-marker'));
});

test('AI 发现 P0 时仍阻断，即使模型声明 PASS', () => {
  const risk = Object.fromEntries(['title', 'location', 'type', 'basis', 'path', 'impact', 'recommendation'].map(field => [field, '明确的凭据外传路径']));
  assert.equal(validateReview({ ...review(), risks: [{ ...risk, level: 'P0', ruleId: 'secret.exposure' }] }).conclusion, 'BLOCK');
});

test('GitHub 到 AI 的完整流程包含契约外的变更文件，不调用检查或扫描 API', async () => {
  const pr = { state: 'open', base: { ref: 'main', sha: 'base' }, head: { ref: 'feature', sha: 'head', repo: { fork: false } }, merge_commit_sha: 'candidate', body: '说明：候选配置调整' };
  const json = value => new Response(JSON.stringify(value));
  const encoded = (value, type) => json({ ...(type ? { type } : {}), encoding: 'base64', content: Buffer.from(value).toString('base64') });
  let modelPrompt;
  let postedReport;
  const deps = createWorkflowDependencies({
    event: { number: 1, pull_request: pr },
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'test-github-token', DEEPSEEK_API_KEY: 'test-deepseek-key' },
    readFileImpl: async () => '审查规则',
    fetchImpl: async (url, options = {}) => {
      if (url.endsWith('/pulls/1')) return json(pr);
      if (url.includes('/compare/base...candidate')) {
        return options.headers.accept.includes('diff')
          ? new Response('diff --git a/deploy/prod.js b/deploy/prod.js\n@@ -1 +1 @@\n-old\n+new')
          : json({ status: 'ahead', merge_base_commit: { sha: 'base' }, files: [{ filename: 'deploy/prod.js' }] });
      }
      if (url.includes('/contents/.pr-security-gate/architecture.json')) return encoded(JSON.stringify(inputs.contract), 'file');
      if (url.includes('/contents/.pr-security-gate/debt.json')) return encoded(JSON.stringify(inputs.baseDebt), 'file');
      if (url.includes('/git/trees/')) return json({ truncated: false, tree: [{ type: 'blob', path: 'deploy/prod.js', sha: url.includes('/base?') ? 'old' : 'new', size: 90 }] });
      if (url.includes('/git/blobs/')) return encoded(url.endsWith('/new')
        ? 'const password = "private-config-value";\nexport const mode = "candidate-production";'
        : 'export const mode = "base-production";');
      if (url.endsWith('/chat/completions')) {
        modelPrompt = JSON.parse(options.body).messages[1].content;
        return json({ choices: [{ message: { content: JSON.stringify(review()) } }] });
      }
      if (url.endsWith('/issues/1/comments?per_page=100')) return json([]);
      if (url.endsWith('/issues/1/comments')) {
        postedReport = JSON.parse(options.body).body;
        return json({ id: 1 });
      }
      throw new Error(`不应调用的 API：${url}`);
    },
  });
  const result = await runReview(deps);
  assert.equal(result.conclusion, 'PASS', result.markdown);
  assert.ok(modelPrompt.includes('candidate-production'));
  assert.ok(modelPrompt.includes('base-production'));
  assert.ok(modelPrompt.includes('候选配置调整'));
  assert.ok(!modelPrompt.includes('private-config-value'));
  assert.ok(postedReport.includes('判定结果：PASS'));
});
