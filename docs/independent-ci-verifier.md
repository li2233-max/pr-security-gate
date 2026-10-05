# Independent CI verification

This reusable workflow provides independently controlled checks for `li2233-max/weixin` when a pull request changes its own CI configuration. It does not trust ordinary checks from a modified workflow and does not change the security or architecture gate's final decision.

## Trust boundary

- The project profile, scanner rules, approved private test commit, paths, and SHA-256 file digests live in this central repository.
- The project caller must exactly match `templates/project-independent-ci-verification.yml`, with the registered 40-character verifier commit substituted for `{{VERIFIER_SHA}}`.
- The reusable workflow reads the candidate repository as data. It does not run the candidate's CI scripts, install its dependencies, load its ignore/config files, or accept caller-selected commands or paths.
- Payment/refund and authorization tests are fetched from the approved private commit, checked against their fixed digests, then run against the candidate implementation in a pinned Node container with no network, token, secrets, runner mount, or writable source tree.
- Test evidence is mapped back only to the exact code paths covered by the pinned suites. The current authorization baseline covers the payment-test access helper and runtime payment policy; it does not prove a new staff/admin endpoint is authorized. Such a change remains subject to the normal security review and needs a separately reviewed test/profile update before it can receive trusted authorization evidence.
- Secret and static scans use fixed central rules and pinned scanner artifacts. Dependency audit reads the candidate lockfile in a credential-free container; no package install or lifecycle scripts run.
- The producer publishes one bounded `verification.json` artifact only after every required check succeeds. The gate accepts it only after validating the Actions run, nested reusable-workflow SHA, exact caller, check suite/jobs, artifact shape, and current repository/base/head/candidate/run/attempt tuple.

The automatically produced checks are `secret-scan`, `sast-config-scan`, `dependency-scan`, `payment-refund-tests`, `authorization-tests`, and `production-hardening-tests`. `architecture-owner-approval` remains a separate human-governed check and is never synthesized by this verifier.

## Limits and rollout

Passing these checks proves only that the centrally fixed checks ran successfully on the recorded candidate. It does not prove the absence of all vulnerabilities, approve architecture/debt changes, or override an AI/security/architecture `BLOCK`. Missing data, API denial, stale SHA, skipped checks, failed scans/tests, unapproved workflow references, or malformed artifacts remain unavailable and block required evidence.

Rollout is staged to avoid a self-approving version cycle: first review and merge the verifier workflow at its exact commit, then register that immutable commit in the gate policy and publish the gate version that validates its provenance. Only after both protected versions are released should the private project copy the caller template and substitute the registered verifier SHA.
