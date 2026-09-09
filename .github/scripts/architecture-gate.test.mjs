import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  collectRelevantPaths,
  createRiskFingerprint,
  evaluateArchitectureGate,
  matchesGlob,
  validateArchitectureContract,
  validateDebtLedger,
} from './architecture-gate.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const EMPTY_DEBT = { version: 1, items: [] };

function contract(overrides = {}) {
  return {
    version: 1,
    contractChangeCheck: 'architecture-owner-approval',
    components: [
      { name: 'a', paths: ['src/a/**'], referenceMarkers: ['@app/a/'], allowedDependencies: ['b'] },
      { name: 'b', paths: ['src/b/**'], referenceMarkers: ['@app/b/'], allowedDependencies: ['a'] },
      { name: 'adapter', paths: ['src/adapter/**'], referenceMarkers: ['@app/adapter/'], allowedDependencies: ['a', 'b'] },
    ],
    resourceRules: [],
    criticalPaths: [],
    debtBudgets: { mode: 'ratchet', total: 10, components: { a: 5, b: 5, adapter: 0 } },
    ...overrides,
  };
}

function file(path, content = '') {
  return { path, content };
}

function debtItem({ ruleId, component, path, level = 'P2', firstSeen = '2026-01-01' }) {
  return {
    fingerprint: createRiskFingerprint({ ruleId, component, path }),
    ruleId,
    component,
    path,
    level,
    firstSeen,
  };
}

function evaluate(options = {}) {
  return evaluateArchitectureGate({
    contract: contract(),
    baseFiles: [],
    candidateFiles: [],
    changedFiles: [],
    passedChecks: [],
    baseDebt: EMPTY_DEBT,
    candidateDebt: EMPTY_DEBT,
    ...options,
  });
}

test('template contracts are valid', async () => {
  const architecture = JSON.parse(await readFile(resolve(HERE, '../../templates/architecture.json'), 'utf8'));
  const debt = JSON.parse(await readFile(resolve(HERE, '../../templates/debt.json'), 'utf8'));

  assert.equal(validateArchitectureContract(architecture).version, 1);
  assert.deepEqual(validateDebtLedger(debt), debt);
});

test('missing base architecture contract blocks instead of compatibility pass', () => {
  const result = evaluateArchitectureGate({ contract: null });

  assert.equal(result.configured, false);
  assert.equal(result.conclusion, 'BLOCK');
  assert.match(result.summary, /base architecture contract is required/i);
});

test('every architecture component must have an explicit debt budget', () => {
  assert.throws(
    () => validateArchitectureContract(contract({
      debtBudgets: { mode: 'ratchet', total: 10, components: { a: 5, b: 5 } },
    })),
    /missing component adapter/,
  );
});

test('glob matching and relevant path collection are language agnostic', () => {
  assert.equal(matchesGlob('src/a/index.ts', 'src/**/index.?s'), true);
  assert.equal(matchesGlob('src/a/nested/file.go', 'src/a/**'), true);
  assert.equal(matchesGlob('test/a.js', 'src/**'), false);
  assert.deepEqual(
    collectRelevantPaths(['README.md', 'src/b/z.py', 'src/a/x.java'], contract()),
    ['src/a/x.java', 'src/b/z.py'],
  );
});

test('two individually acyclic snapshots are blocked when their combination adds a cycle', () => {
  const prA = file('src/a/a.js', "import '@app/b/service'");
  const prB = file('src/b/b.js', "import '@app/a/service'");
  const aOnly = evaluate({ candidateFiles: [prA] });
  const bOnly = evaluate({ candidateFiles: [prB] });
  const result = evaluate({ baseFiles: [prA], candidateFiles: [prA, prB] });

  assert.equal(aOnly.conclusion, 'PASS');
  assert.equal(bOnly.conclusion, 'PASS');
  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.newViolations.some(item => item.kind === 'cycle'), true);
});

test('a newly forbidden dependency is blocked while the same legacy edge is tolerated', () => {
  const architecture = contract({
    components: [
      { name: 'a', paths: ['src/a/**'], referenceMarkers: ['@app/a/'], allowedDependencies: [] },
      { name: 'b', paths: ['src/b/**'], referenceMarkers: ['@app/b/'], allowedDependencies: [] },
    ],
    debtBudgets: { mode: 'ratchet', total: 0, components: { a: 0, b: 0 } },
  });
  const violatingFiles = [file('src/a/a.js', "import '@app/b/service'")];
  const added = evaluate({ contract: architecture, candidateFiles: violatingFiles });
  const legacy = evaluate({ contract: architecture, baseFiles: violatingFiles, candidateFiles: violatingFiles });

  assert.equal(added.conclusion, 'BLOCK');
  assert.equal(added.newViolations.some(item => item.kind === 'dependency'), true);
  assert.equal(legacy.conclusion, 'PASS');
  assert.equal(legacy.existingViolations.some(item => item.kind === 'dependency'), true);
});

test('adding another forbidden dependency path cannot hide behind a legacy component edge', () => {
  const architecture = contract({
    components: [
      { name: 'a', paths: ['src/a/**'], referenceMarkers: ['@app/a/'], allowedDependencies: [] },
      { name: 'b', paths: ['src/b/**'], referenceMarkers: ['@app/b/'], allowedDependencies: [] },
    ],
    debtBudgets: { mode: 'ratchet', total: 0, components: { a: 0, b: 0 } },
  });
  const legacy = file('src/a/legacy.js', "import '@app/b/service'");
  const added = file('src/a/new.js', "import '@app/b/service'");
  const result = evaluate({
    contract: architecture,
    baseFiles: [legacy],
    candidateFiles: [legacy, added],
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.newViolations.some(item => item.kind === 'dependency' && item.path === 'src/a/new.js'), true);
  assert.equal(result.existingViolations.some(item => item.kind === 'dependency' && item.path === 'src/a/legacy.js'), true);
});

test('an unchanged legacy cycle is reported but does not block an unrelated change', () => {
  const files = [
    file('src/a/a.js', "import '@app/b/service'"),
    file('src/b/b.js', "import '@app/a/service'"),
  ];
  const result = evaluate({
    baseFiles: files,
    candidateFiles: [...files, file('README.md', 'documentation only')],
    changedFiles: ['README.md'],
  });

  assert.equal(result.conclusion, 'PASS');
  assert.equal(result.newViolations.length, 0);
  assert.equal(result.existingViolations.some(item => item.kind === 'cycle'), true);
});

test('a new critical resource reference outside its allowed component is blocked', () => {
  const architecture = contract({
    resourceRules: [{
      id: 'secret-adapter-only',
      referenceMarkers: ['process.env.'],
      allowedComponents: ['adapter'],
    }],
  });
  const result = evaluate({
    contract: architecture,
    candidateFiles: [file('src/a/config.js', 'const key = process.env.API_KEY')],
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.newViolations[0].ruleId, 'secret-adapter-only');
  assert.equal(result.newViolations[0].kind, 'resource');
});

test('secret and external-output markers that only become combined are blocked', () => {
  const architecture = contract({
    combinationRules: [{
      id: 'secret-to-external-output',
      sourceMarkers: ['process.env.'],
      sinkMarkers: ['fetch('],
      scope: 'repository',
      components: ['a', 'b'],
    }],
  });
  const baseFiles = [file('src/a/secret.js', 'const token = process.env.API_TOKEN')];
  const result = evaluate({
    contract: architecture,
    baseFiles,
    candidateFiles: [...baseFiles, file('src/b/notify.js', "fetch(notificationUrl, { method: 'POST' })")],
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.newViolations.some(item => item.kind === 'combination'), true);
  assert.equal(result.newViolations.find(item => item.kind === 'combination').details.conservativeCooccurrence, true);
});

test('critical paths require every configured successful check', () => {
  const architecture = contract({
    criticalPaths: [{ id: 'auth-change', paths: ['src/a/auth/**'], requiredChecks: ['auth-tests', 'tenant-tests'] }],
  });
  const missing = evaluate({
    contract: architecture,
    changedFiles: ['src/a/auth/login.js'],
    passedChecks: ['auth-tests'],
  });
  const complete = evaluate({
    contract: architecture,
    changedFiles: ['src/a/auth/login.js'],
    passedChecks: ['auth-tests', 'tenant-tests'],
  });

  assert.equal(missing.conclusion, 'BLOCK');
  assert.equal(missing.newViolations.some(item => item.kind === 'required-check'), true);
  assert.equal(complete.conclusion, 'PASS');
});

test('a contract change cannot approve its own relaxed rules', () => {
  const blocked = evaluate({ contractChanged: true });
  const approved = evaluate({ contractChanged: true, passedChecks: ['architecture-owner-approval'] });

  assert.equal(blocked.conclusion, 'BLOCK');
  assert.equal(blocked.newViolations.some(item => item.ruleId === 'architecture.contract-change-approval'), true);
  assert.equal(approved.conclusion, 'PASS');
});

test('budget mode permits growth within budget but blocks crossing a component budget', () => {
  const one = debtItem({ ruleId: 'p2-one', component: 'a', path: 'src/a/one.js' });
  const two = debtItem({ ruleId: 'p2-two', component: 'a', path: 'src/a/two.js' });
  const architecture = contract({ debtBudgets: { mode: 'budget', total: 5, components: { a: 1, b: 5, adapter: 0 } } });

  const withinBudget = evaluate({
    contract: architecture,
    candidateDebt: { version: 1, items: [one] },
  });
  const overBudget = evaluate({
    contract: architecture,
    candidateDebt: { version: 1, items: [one, two] },
  });

  assert.equal(withinBudget.conclusion, 'PASS');
  assert.deepEqual(withinBudget.debt.newItems.map(item => item.fingerprint), [one.fingerprint]);
  assert.equal(overBudget.conclusion, 'BLOCK');
  assert.equal(overBudget.newViolations.some(item => item.ruleId === 'debt.component-budget'), true);
});

test('ratchet mode blocks any net debt growth even below the numeric budget', () => {
  const item = debtItem({ ruleId: 'new-p2', component: 'a', path: 'src/a/new.js' });
  const result = evaluate({
    candidateDebt: { version: 1, items: [item] },
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.debt.mode, 'ratchet');
  assert.equal(result.newViolations.some(violation => violation.ruleId === 'debt.total-ratchet'), true);
});

test('ratchet is enforced per component even when repository debt total is unchanged', () => {
  const oldA = debtItem({ ruleId: 'old-a', component: 'a', path: 'src/a/old.js' });
  const newB = debtItem({ ruleId: 'new-b', component: 'b', path: 'src/b/new.js' });
  const result = evaluate({
    baseDebt: { version: 1, items: [oldA] },
    candidateDebt: { version: 1, items: [newB] },
  });

  assert.equal(result.debt.baseCount, result.debt.candidateCount);
  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.newViolations.some(item => item.ruleId === 'debt.component-ratchet' && item.component === 'b'), true);
});

test('legacy debt above budget passes when unchanged and blocks only further growth', () => {
  const items = [
    debtItem({ ruleId: 'one', component: 'a', path: 'src/a/one.js' }),
    debtItem({ ruleId: 'two', component: 'a', path: 'src/a/two.js' }),
  ];
  const architecture = contract({ debtBudgets: { mode: 'ratchet', total: 1, components: { a: 1, b: 5, adapter: 0 } } });
  const unchanged = evaluate({
    contract: architecture,
    baseDebt: { version: 1, items },
    candidateDebt: { version: 1, items },
  });
  const worse = evaluate({
    contract: architecture,
    baseDebt: { version: 1, items },
    candidateDebt: {
      version: 1,
      items: [...items, debtItem({ ruleId: 'three', component: 'a', path: 'src/a/three.js' })],
    },
  });

  assert.equal(unchanged.conclusion, 'PASS');
  assert.equal(unchanged.debt.baseCount, 2);
  assert.equal(unchanged.debt.candidateCount, 2);
  assert.equal(worse.conclusion, 'BLOCK');
  assert.equal(worse.newViolations.some(item => item.ruleId === 'debt.component-ratchet'), true);
});

test('current P1/P2 items must be present in the candidate ledger', () => {
  const current = debtItem({ ruleId: 'ai.p1', component: 'repository', path: 'src/unknown/new.js', level: 'P1' });
  const result = evaluate({ currentDebtItems: [current] });

  assert.equal(result.conclusion, 'BLOCK');
  assert.deepEqual(result.debt.missingCurrentItems.map(item => item.fingerprint), [current.fingerprint]);
});

test('debt severity cannot be silently downgraded in the ledger', () => {
  const baseline = debtItem({ ruleId: 'ai.p1', component: 'a', path: 'src/a/risk.js', level: 'P1' });
  const downgraded = { ...baseline, level: 'P2' };
  const result = evaluate({
    baseDebt: { version: 1, items: [baseline] },
    candidateDebt: { version: 1, items: [downgraded] },
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.newViolations.some(item => item.ruleId === 'debt.level-integrity'), true);
});

test('candidate ledger level must match a current AI debt item', () => {
  const current = debtItem({ ruleId: 'ai.p1', component: 'a', path: 'src/a/risk.js', level: 'P1' });
  const recorded = { ...current, level: 'P2' };
  const result = evaluate({
    candidateDebt: { version: 1, items: [recorded] },
    currentDebtItems: [current],
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.debt.mismatchedCurrentItems.length, 1);
  assert.equal(result.newViolations.some(item => item.ruleId === 'debt.current-level-match'), true);
});

test('debt older than the configured maximum age blocks even when its count is unchanged', () => {
  const old = debtItem({
    ruleId: 'legacy.p2',
    component: 'a',
    path: 'src/a/old.js',
    firstSeen: '2025-01-01',
  });
  const architecture = contract({
    debtBudgets: { mode: 'ratchet', total: 10, maxAgeDays: 90, components: { a: 5, b: 5, adapter: 0 } },
  });
  const result = evaluate({
    contract: architecture,
    baseDebt: { version: 1, items: [old] },
    candidateDebt: { version: 1, items: [old] },
    asOf: '2025-05-01T00:00:00Z',
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.deepEqual(result.debt.overdueItems.map(item => item.fingerprint), [old.fingerprint]);
  assert.equal(result.newViolations.some(item => item.ruleId === 'debt.max-age'), true);
});

test('a future firstSeen date cannot be used to evade debt aging', () => {
  const future = debtItem({
    ruleId: 'future.p2',
    component: 'a',
    path: 'src/a/future.js',
    firstSeen: '2099-01-01',
  });
  const architecture = contract({
    debtBudgets: { mode: 'budget', total: 10, maxAgeDays: 90, components: { a: 5, b: 5, adapter: 0 } },
  });
  const result = evaluate({
    contract: architecture,
    candidateDebt: { version: 1, items: [future] },
    asOf: '2026-01-01T00:00:00Z',
  });

  assert.equal(result.conclusion, 'BLOCK');
  assert.equal(result.newViolations.some(item => item.ruleId === 'debt.first-seen-future'), true);
});

test('risk fingerprints normalize separators but preserve Git path case', () => {
  const first = createRiskFingerprint({ ruleId: 'AUTH.Rule', component: 'API', path: '.\\src\\api\\Auth.js' });
  const second = createRiskFingerprint({ ruleId: 'auth.rule', component: 'api', path: 'src/api/Auth.js' });
  const differentCase = createRiskFingerprint({ ruleId: 'auth.rule', component: 'api', path: 'src/api/auth.js' });

  assert.equal(first, second);
  assert.notEqual(first, differentCase);
  assert.throws(
    () => createRiskFingerprint({ ruleId: 'auth.rule', component: 'api', path: '../outside.js' }),
    /parent traversal/,
  );
});
