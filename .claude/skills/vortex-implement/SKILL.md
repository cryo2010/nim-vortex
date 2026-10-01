---
name: vortex-implement
description: >-
  Implement a batch of GitHub issues end to end on one branch: opus agents implement
  (one commit per issue), opus agents adversarially review, findings get fixed, a short
  stress smoke validates, then the PR is opened and CI is monitored to green.
  issues (string): issue numbers and/or ranges, e.g. "450 451" or "300-312".
  Example: "/vortex-implement 450 451" or "/vortex-implement 300-312".
disable-model-invocation: true
arguments: [issues]
argument-hint: "[issue numbers or ranges, e.g. 450 451 or 300-312]"
---

# vortex-implement

Create a branch and dispatch opus agents to implement the following issues, one commit per
issue: $ARGUMENTS. Do not defer any part of these issues; no exceptions. Once complete dispatch
opus agents for an adversarial code review, and fix any issues. Then validate the changes using
a short stress run (e.g. `VORTEX_PROTO=all VORTEX_CLIENT=all VORTEX_SECONDS=10 VORTEX_REPORT_SECONDS=2
nimble stress`). Then open the PR and monitor the CI build. Make hard decisions yourself since
the user is afk, and provide a report afterwards.

`$ARGUMENTS` is the whole issue list (`$issues` is only its first token). If it is empty, ask
the user which issues to implement and stop. Everything below is autonomous: never block on
a question. When a call is genuinely ambiguous, pick the option a careful maintainer would,
note it in the final report under **Decisions**, and keep going.
