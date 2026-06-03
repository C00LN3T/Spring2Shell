# Security Policy

We take the security of **Spring2Shell** seriously. As a tool designed to perform security audits, keeping Spring2Shell itself safe and secure is of paramount importance.

This document outlines how to report vulnerabilities found within the Spring2Shell codebase or dependencies, and which versions are actively supported.

---

## Supported Versions

Only the latest major/minor releases receive security updates and patches. 

| Version | Supported |
| ------- | --------- |
| 2.0.x   | Yes (Active) |
| 1.0.x   | No        |

Please ensure you are running the latest version of Spring2Shell before reporting a potential issue.

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities via public GitHub issues.**

If you discover a vulnerability or security-related bug in this project, please report it responsibly using one of the following methods:

1. **GitHub Private Vulnerability Reporting:**
   - Navigate to the "Security" tab of the repository on GitHub.
   - Click on "Advisories" in the left sidebar.
   - Click "Report a vulnerability" to open a private draft advisory.

2. **Direct Email:**
   - Alternatively, email details of the vulnerability to **maintainer@c00ln3t.org**.
   - If possible, encrypt your message using PGP (key fingerprint or details can be requested via email first).

### What to Include in Your Report

To help us triage and resolve the issue quickly, please include:
- A detailed description of the vulnerability.
- Steps to reproduce (including configuration files, command line flags, or payloads if applicable).
- A proof of concept (PoC) code snippet or command.
- The potential impact (e.g., local file read, denial of service, remote code execution).
- Any details on how this affects specific environments or dependencies.

---

## Our Process

Upon receiving a report, we will:
1. **Acknowledge** receipt of the report within **48 hours**.
2. **Triage** the vulnerability and confirm the impact.
3. **Collaborate** with the reporter to develop a patch or mitigation.
4. **Publish** a security advisory and release a patched version (aiming for release within **30 days** of initial triage).
5. **Credit** the reporter in our release notes and changelog (unless requested otherwise).

Thank you for helping keep Spring2Shell secure!
