# Security Policy

## Supported Versions

Security fixes are generally provided only for the latest release or the current default branch.

Older releases and non-current branches may not receive security updates.

## Operational Diagnostics

Use `secretenv doctor` to review workspace structure, member keys, local trust state, encrypted artifact metadata, and CI environment-key readiness before onboarding, CI rollout, or release work.

The command is read-only for workspace files and local configuration. Secret payloads remain encrypted during artifact checks.

## Reporting a Vulnerability

Please do not report security issues through public GitHub issues, pull requests, or discussions.

To report a vulnerability, please use GitHub Private Vulnerability Reporting for this repository.

When possible, include the following information in your report:

- A clear description of the issue
- The affected version, commit, or configuration
- Steps to reproduce the issue
- A proof of concept or sample exploit, if available
- The potential impact

## Response Process

Reports will be reviewed and assessed based on severity, reproducibility, and impact.

Response targets are as follows:

- Acknowledgement: within 7 days
- Initial assessment: within 30 days

The timeline for remediation or public disclosure will depend on the nature of the issue and the availability of a safe fix or mitigation.

Submitting a report does not guarantee that a fix will be issued, but confirmed issues will be evaluated and handled as appropriate.

## Disclosure Policy

Please avoid public disclosure of the issue until a fix or mitigation is available and users have had a reasonable opportunity to apply it.
