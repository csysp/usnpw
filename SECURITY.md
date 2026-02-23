# Security Policy

## Supported Scope
Security support applies to the latest `main` branch and latest tagged release artifacts.
Reports are taken seriously, false or fully AI generated submissions will be blocked and banned 

## Reporting a Vulnerability
Do not open public issues for unpatched vulnerabilities. Report privately via our email and include affected component, impact, reproduction steps, and a proposed fix if available.

## Handling Process
Reports are acknowledged promptly, triaged by severity, fixed with tests and release notes, and disclosed publicly after a patch is available.

## Release Verification and Signing
Release artifacts include `*.sha256` sidecars from `tools/release.py`. CI also signs checksum sidecars with GPG (workflow: `.github/workflows/release-artifacts.yml`, job: `Sign Checksums`) and publishes `*.sha256.asc` plus `usnpw-release-publickey.asc` in the `usnpw-signatures` artifact.
