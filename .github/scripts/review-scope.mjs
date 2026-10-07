export function enforceMinimumSurfaces(sensitiveSurfaces, changedFiles, policy) {
  const result = Object.fromEntries(
    Object.entries(sensitiveSurfaces).map(([surface, value]) => [surface, { ...value }]),
  );
  if (!Array.isArray(changedFiles)) throw new Error('changedFiles 必须是数组');
  for (const classifier of policy.surfaceClassifiers) {
    const pattern = new RegExp(classifier.pathPattern, 'i');
    const matchedPath = changedFiles.find(path => typeof path === 'string' && pattern.test(path.replaceAll('\\', '/')));
    if (matchedPath && result[classifier.surface]?.status === '未涉及') {
      result[classifier.surface] = {
        status: '涉及',
        reason: `机器策略 ${classifier.id} 命中变更路径 ${matchedPath.slice(0, 300)}；模型不得降级。`,
      };
    }
  }
  return result;
}

