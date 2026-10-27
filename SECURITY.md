# Security Policy

## Supported Versions

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 1.0.x   | :white_check_mark: | Current active release branch |

---

## Architecture & Security Model

Domain Lockout Helper is engineered for high-security environments, including healthcare (HIPAA), education (FERPA/CIPA), financial institutions, and enterprise networks.

### 1. 100% Offline & Domain-Local Processing
- All authentication logs, Kerberos preauth failures (4771), NTLM logon failures (4625), lockout events (4740), and unlock events (4767) are queried directly from the local domain's Primary Domain Controller (PDC) emulator.
- No telemetry, analytics, crash logs, or diagnostic records are ever sent across the public internet.

### 2. Least-Privilege & Non-Destructive Operations
- Event querying and Active Directory analysis perform standard LDAP and Event Log read operations.
- The only write operations performed are explicit administrator actions:
  - **Unlock User:** Clears the user's `lockoutTime` attribute on the domain controller.
  - **Reset Password:** Updates the user's password using the standard Windows API (`SetPassword`) when explicitly confirmed by the administrator.

### 3. Enterprise EDR Compatibility
- The application is specifically designed to run without triggering endpoint detection and response (EDR) false positives (such as SentinelOne, CrowdStrike Falcon, Carbon Black, and Microsoft Defender for Endpoint).
- Broad directory sweeps (e.g., querying all domain computer objects) are intentionally omitted in favor of direct caller IP / hostname DNS lookup and ICMP ping.

---

## Reporting a Vulnerability

If you discover a security vulnerability or security-related issue in this project:

1. **Do not disclose the issue publicly** in GitHub issues or discussions.
2. Please contact the project maintainers directly with a detailed summary, including:
   - Steps to reproduce or proof-of-concept
   - Impact assessment
   - Target environment details (Windows Server version, forest/domain functional level)
3. You will receive an acknowledgment within 48 hours, followed by a mitigation plan and coordinated disclosure timeline.
