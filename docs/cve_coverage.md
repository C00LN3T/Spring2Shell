# CVE Coverage

Current payload coverage in `data/payloads/cve_payloads.json`.

| CVE | Vulnerability | Affected Software | Type | Severity | Payload Variants |
|---|---|---|---|---|---|
| **[CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)** | SpEL Injection — RCE via GraphQL/Spring endpoints | Spring Framework | 🔴 RCE | 💥 Critical | `8` |
| **[CVE-2025-66478](https://nvd.nist.gov/vuln/detail/CVE-2025-66478)** | GraphQL-specific SpEL injection | Spring + GraphQL | 🔴 RCE | 💥 Critical | `3` |
| **[CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965)** | Spring4Shell — ClassLoader data binding RCE | Spring Framework < 5.3.18, < 5.2.20 | 🔴 RCE | 💥 Critical | `2` |
| **[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)** | Log4Shell — JNDI injection | Apache Log4j 2.0-beta9 to 2.14.1 | 🔴 RCE | 💥 Critical | `6` |
| **[CVE-2022-42889](https://nvd.nist.gov/vuln/detail/CVE-2022-42889)** | Text4Shell — Commons Text interpolation RCE | Apache Commons Text < 1.10.0 | 🔴 RCE | 💥 Critical | `3` |

## Adding Coverage for a New CVE

1. Research the CVE — understand the injection point, affected software, affected versions.
2. Add an entry to `data/payloads/cve_payloads.json`:
   ```json
   "CVE-YYYY-NNNNN": {
     "_description": "One-line description. Replace COMMAND with test command.",
     "payloads": [
       "payload_template_1",
       "payload_template_2"
     ]
   }
   ```
3. Add relevant endpoints to `data/endpoints/cve_endpoints.txt`.
4. Update this table.
5. Commit with a reference to the CVE advisory URL in the commit message.
