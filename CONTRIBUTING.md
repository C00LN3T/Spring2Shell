# Contributing to Spring2Shell

Thank you for your interest in contributing to **Spring2Shell**! Contributions from the security research and developer community are vital to keeping this project robust, performant, and up-to-date.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating in this project.

---

## 📖 Table of Contents

1. [Our Policy on Responsible Disclosure](#🛡️-our-policy-on-responsible-disclosure)
2. [How Can I Contribute?](#how-can-i-contribute)
3. [Local Development Setup](#local-development-setup)
4. [Code Quality & Linting](#code-quality--linting)
5. [Testing Guidelines](#testing-guidelines)
6. [Pull Request Process](#pull-request-process)

---

## 🛡️ Our Policy on Responsible Disclosure

Because Spring2Shell is a vulnerability scanner and security assessment tool:
- **Do NOT open public issues for security vulnerabilities found within Spring2Shell itself.**
- Instead, please refer to our [Security Policy](SECURITY.md) for details on how to report vulnerabilities privately.

---

## How Can I Contribute?

* **Reporting Bugs:** First, search the existing issues. If your problem hasn't been reported, open an issue using the **Bug Report** template.
* **Suggesting Features:** Open an issue using the **Feature Request** template, detailing the proposed change and its benefits.
* **Adding Payloads / Signatures:** We welcome PRs that update `data/payloads/cve_payloads.json` to cover new CVEs or add evasion techniques.
* **Submitting Pull Requests:** Fix open issues or implement approved feature requests.

---

## Local Development Setup

To set up a local development environment:

1. **Fork and Clone** the repository:
   ```bash
   git clone https://github.com/your-username/Spring2Shell.git
   cd Spring2Shell
   ```

2. **Set up a Virtual Environment**:
   ```bash
   make venv
   source .venv/bin/activate
   ```

3. **Install Dependencies in Editable Mode**:
   ```bash
   make install-dev
   ```

---

## Code Quality & Linting

We maintain high code quality and strict formatting standards using `ruff` and `mypy`. Before submitting a pull request, ensure your code passes all checks:

- **Format Code**:
  ```bash
  make format
  ```
- **Lint Code**:
  ```bash
  make lint
  ```
- **Type Checking**:
  ```bash
  make typecheck
  ```
- **Run All Quality Checks**:
  ```bash
  make check
  ```

---

## Testing Guidelines

We use `pytest` for unit and integration testing. Any new features or bug fixes must include corresponding tests.

- **Run all tests (with coverage report)**:
  ```bash
  make test
  ```
- **Run unit tests only**:
  ```bash
  make test-unit
  ```
- **Run integration tests only**:
  ```bash
  make test-integration
  ```

Ensure that coverage does not drop as a result of your contribution.

---

## Pull Request Process

1. **Branch Naming**: Use descriptive branch names (e.g., `feature/add-cve-2026-xxxx` or `fix/connection-timeout`).
2. **Commit Messages**: Write clear, descriptive commit messages matching standard conventions (e.g., `feat: add scanner support for CVE-2026-XYZ`).
3. **Update Documentation**: If your change introduces new flags, CLI modes, or configuration values, update the `README.md` and relevant help screens.
4. **Pass CI/CD**: Ensure all tests and lints pass.
5. **Open Pull Request**: Fill out the provided [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md) completely so the maintainers can review your changes efficiently.
