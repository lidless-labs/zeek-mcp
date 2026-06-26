# Contributing to zeek-mcp

zeek-mcp is a Model Context Protocol server that exposes Zeek and Suricata network security monitoring logs to AI clients. Patches are welcome. Before you start, please skim this file so we both spend our time on the right things.

## What kinds of changes land easily

- **Bug fixes** in the parsers (JSON/TSV), query engine, CIDR/wildcard filters, analytics, or any tool handler.
- **New Zeek log type support** or sharper parsing of existing types.
- **New detections** that are statistically grounded and have test coverage (beaconing, tunneling, anomaly, baseline, JA3, and friends).
- **Better tool descriptions** so the model picks the right tool more often.
- **Test coverage** for any of the above.

## What needs a conversation first

- **A new MCP tool, resource, or prompt.** These are the public surface. Open an issue describing the user story first, so we can agree on the name and shape before you build it.
- **Breaking changes** to tool names, input schemas, or environment variable names. Renaming a tool breaks every client config that references it.
- **A new runtime dependency.** zeek-mcp deliberately keeps its dependency surface small. Justify the addition in an issue first.

## What does not land

- Personal details, hostnames, account IDs, real private IPs, or live credentials in code, tests, or sample data. Use `192.0.2.0/24` (RFC 5737) and generic hostnames in examples. CI rejects leaks.
- Tools that write to Zeek or Suricata data on disk, or that capture or modify live traffic. zeek-mcp is read-only against telemetry; the only writes are the explicit, credentialed TheHive/MISP tools.
- AI co-authorship trailers on commits (`Co-Authored-By: <model>`). Conventional commits only.

## Local dev

```bash
git clone https://github.com/lidless-labs/zeek-mcp.git
cd zeek-mcp
npm install
npm run build
npm test
```

Run the server against the bundled sample data without a live sensor:

```bash
ZEEK_LOG_DIR=./test-data npm run dev
```

Generate fresh mock logs to test against:

```bash
npm run generate-logs
```

## Adding a tool

Tools are grouped by domain under `src/tools/<domain>.ts`, each file exporting a `register<Domain>Tools(server, config)` function that calls `server.tool(name, description, schema, handler)`. To add one:

1. Add the handler to the appropriate `src/tools/*.ts` file (or create a new one).
2. Wire its `register*` function into `src/index.ts`.
3. Add a row to the tool table in `README.md` **and** update the tool count in the header and the `## Tools` lede so they stay accurate.
4. Add a test under `tests/`.
5. Add a `## [Unreleased]` entry to `CHANGELOG.md`.

## Filing issues

Use the templates under `.github/ISSUE_TEMPLATE/`. Before posting any tool output or logs, remove tokens, private hostnames, private repo names, and real private IPs.

## License

By contributing you agree that your contribution is licensed under the MIT License, same as the rest of the repo.
