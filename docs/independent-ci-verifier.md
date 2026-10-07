# Independent CI verification

This reusable workflow provides independently controlled checks for `li2233-max/weixin` when a pull request changes its own CI configuration. It does not trust ordinary checks from a modified workflow and does not change the security or architecture gate's final decision.

## Trust boundary

- The project profile, approved scan roots, and pinned tool identities live in this central repository.
- The project caller must exactly match `templates/project-independent-ci-verification.yml`, with the registered 40-character verifier commit substituted for `{{VERIFIER_SHA}}`.
- The reusable workflow reads the candidate repository as data. It does not run the candidate's CI scripts, install its dependencies, load its ignore/config files, or accept caller-selected commands or paths.
- Secret scanning uses a pinned Gitleaks artifact. Dependency audit reads the candidate lockfile in a pinned Node container; no package install or lifecycle scripts run. The production-hardening check inspects a fixed set of application and CI controls without running candidate code.
- Payment/refund tests, authorization tests, and Semgrep static scanning are not part of this verifier. A successful manifest provides no evidence that those checks ran.
- The producer publishes one bounded `verification.json` artifact only after every required check succeeds. The gate accepts it only after validating the Actions run, nested reusable-workflow SHA, exact caller, check suite/jobs, artifact shape, and current repository/base/head/candidate/run/attempt tuple.
- The caller grants `actions: read`, and the manifest publication job requests it to read the current workflow run identity. A PR run's `head_sha` binds to the PR branch head; the manifest's candidate SHA binds separately to the current merge commit.

The automatically produced checks are `secret-scan`, `dependency-scan`, and `production-hardening-tests`. `architecture-owner-approval` remains a separate human-governed check and is never synthesized by this verifier.

## Limits and rollout

Passing these checks proves only that the centrally fixed checks ran successfully on the recorded candidate. It does not prove the absence of all vulnerabilities, approve architecture/debt changes, or override an AI/security/architecture `BLOCK`. Missing data, API denial, stale SHA, skipped checks, failed scans/tests, unapproved workflow references, or malformed artifacts remain unavailable and block required evidence.

Rollout is staged to avoid a self-approving version cycle: first review and merge the verifier workflow at its exact commit, then register that immutable commit in the gate policy and publish the gate version that validates its provenance. Only after both protected versions are released should the private project copy the caller template and substitute the registered verifier SHA.
