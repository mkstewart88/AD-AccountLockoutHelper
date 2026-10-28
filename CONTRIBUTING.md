# Contributing to Domain Lockout Helper

Thank you for your interest in contributing to **Domain Lockout Helper & Root Cause Investigator**.

This utility is designed for mission-critical enterprise and educational Active Directory environments. To maintain reliability across diverse domains, all contributions must adhere to the core design principles outlined below.

---

## Core Engineering Principles

### 1. Zero External Dependencies & Zero Runtime Installation
- The project must run out-of-the-box on default Windows installations without requiring RSAT (Remote Server Administration Tools), external PowerShell modules (e.g., ActiveDirectory module), or NuGet packages.
- Always use native .NET Framework directory services (`System.DirectoryServices`, `System.DirectoryServices.AccountManagement`) and native Windows Event Log readers (`System.Diagnostics.Eventing.Reader`).

### 2. C# 5 / .NET Framework 4.x Backward Compatibility
- `Program-Code.cs` is compiled using the Windows built-in compiler (`csc.exe` located in `%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`).
- **Do not use C# 6+ language features**:
  - Do NOT use string interpolation (`$"..."`). Use `string.Format("...", ...)`.
  - Do NOT use the null-conditional operator (`?.`). Use explicit `if (obj != null)` checks.
  - Do NOT use `nameof()`. Use explicit string literals.
  - Do NOT use auto-property initializers (`public int Count { get; set; } = 0;`). Initialize in constructors.
  - Do NOT use expression-bodied members (`=>`).
- Target Framework: .NET Framework 4.0 through 4.8.1.

### 3. Enterprise EDR & Security Baseline Safety
- **No Broad Reconnaissance Queries:** Never introduce recursive LDAP sweeps (such as `(objectCategory=computer)` querying operating systems across the directory), which trigger MITRE ATT&CK T1018 alerts in enterprise EDRs (e.g., SentinelOne, CrowdStrike, Microsoft Defender for Endpoint).
- **Domain Controller Targeting:** Scope event log queries to the domain's Primary Domain Controller (PDC) emulator.
- **Privacy & Compliance:** The application must remain 100% offline and deterministic. No authentication logs, usernames, IP addresses, or computer names may ever be transmitted outside the local machine or domain boundary.

---

## Development Workflow

### Compiling `AccountLockoutHelper.exe` from Source (`Program-Code.cs`)
1. Double-click `Build-Executable.cmd` to compile the source code automatically using the built-in Microsoft .NET C# compiler (`csc.exe`).
2. Alternatively, run the compiler manually from Command Prompt:
```cmd
%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /out:AccountLockoutHelper.exe Program-Code.cs
```
3. Verify that compilation completes with **0 errors and 0 warnings**.

### Testing Execution
Run the compiled `AccountLockoutHelper.exe` on a domain-joined PC to verify the GUI launches and connects to Active Directory.

---

## Submitting Pull Requests

1. Fork the repository and create your branch from `main`.
2. Ensure your code passes all lint and build checks.
3. Test your changes against a domain-joined test environment or lab domain controller.
4. Open a Pull Request with a clear description of the problem, the root cause, and the verification steps performed.
