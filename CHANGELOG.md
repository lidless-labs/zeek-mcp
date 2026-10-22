# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Require Node.js 22 or newer. CI tests Node 22 and 24, checks types and production dependency advisories, and pins GitHub Actions to commit SHAs.
- Refresh the MCP SDK and HTTP dependencies, and report the MCP server version from package metadata.


### Changed
- README rewritten for adoption: leads with what/why/how-it-differs, adds a "What it does" overview, a copy-paste `npx -y zeek-mcp` MCP client config block, a "Why not something else?" comparison, and a "What zeek-mcp is not" boundaries section. Badges, clone URLs, and CI links now point at the `lidless-labs` org.
- Corrected the documented tool count from 25 to the actual **39 tools**, and added the previously undocumented JA3 fingerprinting, network baseline, PCAP replay, TheHive, and MISP tools to the tool tables.

### Added
- Maintainer-health files: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub issue templates (bug, feature, config with blank issues disabled and contact links), a pull request template with a no-PII content checklist, and this changelog.
