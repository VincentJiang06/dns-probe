# Security and diagnostic data

DNS Probe accepts untrusted DNS responses and produces diagnostic reports. A full report may contain private DNS names, resolver and interface addresses, paths, certificate information and returned TXT/EDE text. Treat reports as potentially sensitive. Use synthetic examples in public issues.

The maintained line is the latest 1.x release. This repository does not automatically alter DNS settings, execute suggested commands, download updates or send telemetry. Network requests are controlled by explicit targets, routing policy and resource budgets. See docs/STATUS.md for observer and validation limits.

For a vulnerability, use the repository's **Security → Report a vulnerability** private reporting feature once the maintainer has enabled it. Do not include exploit payloads or private network evidence in a public issue. If private reporting is unavailable, open an issue asking the maintainer to enable a private reporting channel, without sensitive details. No contact address is invented here.

Useful reports include the affected version, minimal synthetic reproduction, impact and expected behavior. Ordinary DNS failures belong in bug reports; a timeout alone is not evidence of a security vulnerability.
