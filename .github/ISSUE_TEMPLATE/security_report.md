---
name: Security vulnerability
about: Report a security vulnerability (use this only for LOW severity issues - for higher severity, email security@example.com)
title: '[SECURITY] '
labels: security, needs-triage
assignees: ''

---

⚠️ **IMPORTANT**: This template is only for LOW severity security issues. For MEDIUM, HIGH, or CRITICAL severity vulnerabilities, please report them privately via email to security@example.com as described in our [Security Policy](../../SECURITY.md).

## Vulnerability Description

A clear and concise description of the vulnerability.

## Severity Assessment

- **CVSS Score**: [If known]
- **Severity**: LOW (if higher, please email instead of using this form)
- **Attack Vector**: [Local/Network/Physical]
- **Attack Complexity**: [Low/High]
- **Privileges Required**: [None/Low/High]
- **User Interaction**: [None/Required]

## Affected Components

- **Affected Module**: [e.g., collectors::linux, security::analyzer]
- **Affected Versions**: [e.g., 0.1.0 - 0.1.5]
- **Platform Specific**: [Yes/No - if yes, which platforms?]

## Steps to Reproduce

1. Install version X
2. Run command Y
3. Observe vulnerability

## Proof of Concept

```rust
// If applicable, provide minimal code that demonstrates the issue
// DO NOT include actual exploits
```

## Impact

Describe the potential impact of this vulnerability:
- What can an attacker do?
- What data could be exposed?
- What privileges could be gained?

## Mitigation

Are there any workarounds or mitigations users can apply?

## Fix Suggestion

If you have suggestions on how to fix this vulnerability, please describe them here.

## References

- Related CVEs (if any)
- Similar vulnerabilities in other software
- Relevant security research

## Disclosure Timeline

- Date discovered:
- Date reported:
- Expected disclosure date:

---

By submitting this issue, I confirm that:
- [ ] This is a LOW severity issue (otherwise I would email security@example.com)
- [ ] I have read the [Security Policy](../../SECURITY.md)
- [ ] I will coordinate disclosure with the maintainers