# Security Policy

## Supported versions

Only the latest release on the `main` branch receives security fixes. Pin to a released version on npm if you need a known-good build.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Email **me@solomonneas.dev** with: <!-- content-guard: allow pii/email -->

- A short description of the issue.
- Steps to reproduce (or a minimal proof of concept).
- The version or commit you tested against.
- Whether you would like to be credited in the release notes.

You should get an acknowledgment within 72 hours. If you do not, please follow up; the mail may have been filtered.

## In scope

- Path traversal or symlink-attack flaws in log resolution, archive reading, or `pcap_analyze` (which must confine all filenames to `PCAP_DIR`).
- Command injection in the PCAP replay path (Zeek is invoked with an argv array and no shell; report any way to break that).
- Leaks of credentials or tokens (`MISP_API_KEY`, `THEHIVE_API_KEY`) into logs, error messages, or tool output.
- TLS verification bypasses that escape their intended scope (the `*_VERIFY_SSL=false` switches must only affect the MISP or TheHive connection they name, never global TLS state).
- Any tool that mutates Zeek or Suricata data on disk (read-only tools must stay read-only).

## Out of scope

- Bugs in Zeek, Suricata, TheHive, MISP, or the MCP SDK; report those to their respective projects.
- Issues that require an attacker to already have read access to your sensor's logs or write access to your MCP client config.
- The optional TheHive and MISP write tools creating alerts, cases, or events when you have supplied credentials and the model is instructed to use them. That is the documented behavior; gate access with your client's tool permissions.

## Disclosure

We aim to ship a fix within 14 days of confirming a valid report. A coordinated disclosure timeline can be negotiated for issues that need longer.
