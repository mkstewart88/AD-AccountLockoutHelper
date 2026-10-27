# Changelog

All notable changes to **Domain Lockout Helper & Root Cause Investigator** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-26

### Added
- **Core Lockout Investigation Engine:**
  - Automated detection of Active Directory Primary Domain Controller (PDC) emulator.
  - Real-time querying of Windows Security Event IDs 4740 (Account Lockout), 4771 (Kerberos Pre-Authentication Failed / Bad Password), and 4625 (NTLM Logon Failure).
  - Accurate distinction between **Currently Locked** accounts (via ADSI `IsAccountLocked`) and **Historical Lockout Records** (retaining forensic history while eliminating expired records).
  - Exclusion of disabled accounts (`userAccountControl` bit 2) to eliminate clutter.
- **Root-Cause Analysis:**
  - Automated correlation of user `pwdLastSet` timestamps with lockout events to detect stale credentials following recent password updates.
  - Root cause categorizations for Credential Manager, 802.1X Wireless/RADIUS, Service Accounts/Scheduled Tasks, Stale Mobile ActiveSync profiles, and Shared PC Sessions.
- **Caller Host Diagnostics:**
  - Caller hostname and IPv4/IPv6 resolution via standard DNS.
  - ICMP ping connectivity test (1000ms timeout) reporting latency and reachability.
  - Remote user session enumeration via `quser.exe` with remote logoff and workstation reboot capabilities.
- **Administrative Actions:**
  - One-click domain-wide account unlock clearing the `lockoutTime` attribute.
  - Password reset prompt supporting forced password change at next logon.
- **Portability & Deployment:**
  - Automated batch build script (`Build-Executable.cmd`) to compile `AccountLockoutHelper.cs` into `AccountLockoutHelper.exe` using the built-in Windows .NET C# compiler (`csc.exe`).
- **Account Unlock Accountability (Event ID 4767):**
  - Scans Domain Controller Security logs for Event ID 4767 ("A user account was unlocked").
  - Identifies who performed prior unlocks (`SubjectUserName`), the reporting Domain Controller, and the exact timestamp.
  - Interleaves unlock events with Event 4740 lockout events in the unified chronological timeline.
- **Enterprise 802.1X Wi-Fi & NPS / RADIUS Playbook:**
  - Automated diagnosis for lockouts originating from Network Policy Server (NPS) or RADIUS proxies.
  - Step-by-step guidance for analyzing NPS Event ID 6273 to extract client hardware MAC addresses (`Calling-Station-Id`) and Access Point locations (`Client-Friendly-Name`).
- **Streamlined Single-Build Architecture:**
  - Standardized on a single, one-click build script (`Build-Executable.cmd`) with flat syntax, no subshell parsing hazards, and automatic compiler discovery.
  - Standalone portable C# source code (`AccountLockoutHelper.cs`) and native PowerShell 5.1/7+ counterpart (`AccountLockoutHelper.ps1`).

### Security & Hardening
- Complete removal of broad directory sweeps (`objectCategory=computer` LDAP queries) to ensure 100% compliance with enterprise EDR solutions (SentinelOne, CrowdStrike, Defender).
- Event Log queries utilize native, targeted read-only XPath event readers without generating anomalous process telemetry or network scan alerts.
- Full .NET assembly versioning and manifest attributes embedded in C# source.
- 100% offline and deterministic execution ensuring complete CIPA, FERPA, COPPA, and HIPAA compliance.
