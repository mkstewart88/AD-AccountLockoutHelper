# Changelog

All notable changes to **Domain Lockout Helper & Root Cause Investigator** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.3] - 2026-10-29

### Added
- **Version Numbering in Window Title & Releases:**
  - Added explicit version indicator `(v1.0.3)` to the application window title bar so administrators can instantly verify their deployed executable version against unversioned legacy copies.
- **Enhanced Tabular Account & Computer Forensics:**
  - Structured Active Directory attributes and computer records into aligned two-column tables (`FIELD | VALUE`) with monospace typography and visual header divider bars.
  - Formatted the Event Audit Log Timeline into dedicated columns with color-highlighted status flags.
  - Standardized Notable Client IPs and Caller Computers to uniformly display `IP -> Hostname (or (cannot resolve)) | N event(s) | Latest: YYYY-MM-DD HH:MM:SS`.
  - Enabled QUSER remote session queries and AD computer inspection for Notable Client IPs.

## [1.1.0] - 2026-10-29

### Added
- **Expanded Forensic Event Suite:**
  - Integrated Security Event IDs 4624 (Logon Success), 4625 (Logon Failure), 4771 (Kerberos Pre-Auth Failure), 4740 (Account Lockout), 4776 (NTLM Credential Validation), 4767 (Account Unlocked), and 4724 (Administrator Password Reset).
  - Bounded targeted XPath event readers (recent 7 days, max 50 events per DC) ensuring zero MDR/EDR behavioral alerts.
  - Real-time post-unlock logon verification (Event 4624) resolving Active Directory `lastLogonTimestamp` replication lag, with inline guidance explaining local workstation screen unlock (Logon Type 7) Kerberos TGT caching.
- **Dual-Box Caller Computer & Notable IP Separation:**
  - Dedicated **Caller Computers (Workstations / Servers)** list box strictly for managed Windows hostnames.
  - Dedicated **Notable Client IPs (Event Log Source IPs)** list box for client IP addresses originating from authentication events.
- **Asynchronous Reverse DNS (PTR) Resolution:**
  - Non-blocking reverse DNS lookups on background thread displaying inline hostname mappings (e.g., `10.1.20.45 -> WKSTN-042.corp.contoso.com`).
- **Targeted Active Directory Computer Object Inspection:**
  - Real-time single-object AD lookup (`(&(objectCategory=computer)(sAMAccountName=SHORTNAME$))`) determining OS, version, OU path, and device category (Windows Server vs. Windows Workstation vs. Non-domain Linux/Chromebook/mobile endpoint).
- **Intelligent Machine Deduplication & Event Aggregation:**
  - Automatically deduplicates and merges IPs matching physical caller computers (e.g. `WKSTN-042` appearing once in Caller Computers with combined event counts and Associated Client IPs listed).
  - Prevents redundant IP listings when multiple network adapters (Ethernet and Wi-Fi) or DHCP leases authenticate the same physical machine.
- **Structured Tabular Layout with Aligned Columns & Visual Dividers:**
  - Standardized on Consolas monospace font with horizontal/vertical scrolling to eliminate awkward word-wrap breaks across dates, timestamps, and numbers.
  - Aligned two-column table (`FIELD | CURRENT AD VALUE`) with clean column borders and visual header divider bars.
  - Formatted Event Audit Log Timeline into dedicated columns (`DATE & TIME | EVENT ID & TYPE | CALLER / IP / WORKSTATION | STATUS / RESULT / CODE | DOMAIN CONTROLLER`).
  - Color-highlighted status flags: bold Red for active lockouts and bad password failures, bold Green for unlocks and successful logons, Sky Blue for section banners, and Amber for pre-auth/NTLM notices.
- **Password Reset Enhancements:**
  - Added checkbox to require the user to change their password at next logon (`user.ExpirePasswordNow()`).

### Fixed
- Fixed C# compiler variable scope error (`CS0103: infrastructureNote`) in `RenderComputerAdDetails`.
- Fixed Column 2 TableLayoutPanel layout overlap where action buttons collided with the Target Details rich text box at cell (0, 2).
- Fixed ListBox string caching so reverse DNS resolved hostnames immediately render upon background thread completion.
- Removed unused private GroupBox fields (`_grpAccounts`, `_grpComputers`, `_grpSessions`) eliminating compiler warnings.

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
  - Automated batch build script (`Build-Executable.cmd`) to compile `Program-Code.cs` into `AccountLockoutHelper.exe` using the built-in Windows .NET C# compiler (`csc.exe`).
- **Account Unlock Accountability (Event ID 4767):**
  - Scans Domain Controller Security logs for Event ID 4767 ("A user account was unlocked").
  - Identifies who performed prior unlocks (`SubjectUserName`), the reporting Domain Controller, and the exact timestamp.
  - Interleaves unlock events with Event 4740 lockout events in the unified chronological timeline.
- **Enterprise 802.1X Wi-Fi & NPS / RADIUS Playbook:**
  - Automated diagnosis for lockouts originating from Network Policy Server (NPS) or RADIUS proxies.
  - Step-by-step guidance for analyzing NPS Event ID 6273 to extract client hardware MAC addresses (`Calling-Station-Id`) and Access Point locations (`Client-Friendly-Name`).
- **Streamlined Single-Build Architecture:**
  - Standardized on a single, one-click build script (`Build-Executable.cmd`) with flat syntax, no subshell parsing hazards, and automatic compiler discovery.
  - Dedicated standalone C# source code (`Program-Code.cs`) compiling directly to native executable (`AccountLockoutHelper.exe`).

### Security & Hardening
- Complete removal of broad directory sweeps (`objectCategory=computer` LDAP queries) to ensure 100% compliance with enterprise EDR solutions (SentinelOne, CrowdStrike, Defender).
- Event Log queries utilize native, targeted read-only XPath event readers without generating anomalous process telemetry or network scan alerts.
- Full .NET assembly versioning and manifest attributes embedded in C# source.
- 100% offline and deterministic execution ensuring complete CIPA, FERPA, COPPA, and HIPAA compliance.
