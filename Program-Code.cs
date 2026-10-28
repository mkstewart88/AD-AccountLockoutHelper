// =============================================================================
// DOMAIN LOCKOUT HELPER & ROOT CAUSE INVESTIGATOR
// Standalone Native Windows Application (.NET Framework 4.0 / 4.5+ Compatible)
// Copyright (c) 2026 The Domain Lockout Helper Project Contributors. Licensed under the Apache License, Version 2.0.
// See NOTICE for commercial use acknowledgement terms.
//
// DISCLAIMER: USE ENTIRELY AT YOUR OWN RISK. PROVIDED "AS IS" WITHOUT WARRANTY.
// The author assumes ABSOLUTELY ZERO LIABILITY AND ZERO RESPONSIBILITY FOR LITERALLY
// ANY ACTION, OPERATION, ERROR, OR OUTCOME THIS PROGRAM COULD POSSIBLY PERFORM OR CAUSE.
// The operator assumes 100% of all risk. Sole responsibility of the operator to review all code.

//
// COMPILER TARGET & COMPATIBILITY SPECIFICATION:
// -----------------------------------------------------------------------------
// - Compiler: Microsoft (R) Visual C# Compiler (csc.exe) shipped natively in:
//   %SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
// - Language Level: C# 5 (ISO/IEC 23270:2006 / ECMA-334)
// - Framework Target: .NET Framework 4.0, 4.5, 4.6, 4.7, 4.8, 4.8.1
// - Supported OS: Windows 11, Windows 10, Windows Server 2025/2022/2019/2016
// - Runtime Footprint: Zero external dependencies, zero NuGet packages, no runtime install.
//
// MAINTENANCE & CODING RULES FOR FUTURE DEVELOPERS:
// -----------------------------------------------------------------------------
// 1. DO NOT USE C# 6+ FEATURES:
//    - DO NOT use string interpolation ($"hello {name}"). Use string.Format("hello {0}", name).
//    - DO NOT use null-conditional operator (obj?.Prop). Use if (obj != null) check.
//    - DO NOT use nameof() operator. Use explicit string literals.
//    - DO NOT use auto-property initializers (public int X { get; set; } = 0).
//      Initialize properties inside constructors.
//    - DO NOT use expression-bodied method/property syntax (int Foo => 10;).
// 2. ENCODING & PARSER INTEGRITY:
//    - Keep this source file strictly in 7-bit ASCII or UTF-8 without BOM.
//    - Do not embed unicode glyphs/emojis in strings; use clean bracketed tags
//      (e.g., [WI-FI / RADIUS], [SHARED PC SESSION], [CREDENTIAL MANAGER]).
// 3. COMPILATION COMMAND:
//    csc.exe /target:winexe /platform:anycpu /optimize+ /out:AccountLockoutHelper.exe
//    Program-Code.cs /reference:System.dll,System.Core.dll,System.DirectoryServices.dll,
//    System.DirectoryServices.AccountManagement.dll,System.Windows.Forms.dll,System.Drawing.dll
// =============================================================================

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Account Lockout Helper")]
[assembly: AssemblyDescription("Active Directory Account Lockout Diagnostic Tool")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Microsoft Windows Administration")]
[assembly: AssemblyProduct("Account Lockout Helper")]
[assembly: AssemblyCopyright("Copyright (C) 2026")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: ComVisible(false)]

namespace DomainLockoutHelper
{
    public class Program
    {
        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }


    public class UserRecord
    {
        public string SamAccountName { get; set; }
        public string DisplayName { get; set; }
        public string UserPrincipalName { get; set; }
        public string EmailAddress { get; set; }
        public string Department { get; set; }
        public string Title { get; set; }
        public bool Enabled { get; set; }
        public bool IsCurrentlyLocked { get; set; }
        public int BadPasswordCount { get; set; }
        public DateTime? LastBadPasswordAttempt { get; set; }
        public DateTime? PasswordLastSet { get; set; }
        public DateTime? LastLogonTimestamp { get; set; }
        public DateTime? AccountExpires { get; set; }
        public bool PasswordNeverExpires { get; set; }
        public bool MustChangePasswordAtNextLogon { get; set; }
        public List<string> MemberOfGroups { get; set; }
        public int EventCount { get; set; }
        public DateTime? LatestEventTime { get; set; }
        public string LatestCaller { get; set; }
        public string LatestDC { get; set; }
        public string ResultantPSO { get; set; }
        public List<LockoutEventItem> Events { get; set; }

        public UserRecord()
        {
            Events = new List<LockoutEventItem>();
            MemberOfGroups = new List<string>();
            Enabled = true;
        }

        public override string ToString()
        {
            string status = IsCurrentlyLocked ? "[LOCKED]" : "[HISTORICAL]";
            string callerInfo = !string.IsNullOrEmpty(LatestCaller) ? "  |  Caller: " + LatestCaller : "";
            return string.Format("{0} {1} ({2})  |  {3} event(s){4}", status, DisplayName ?? SamAccountName, SamAccountName, EventCount, callerInfo);
        }
    }

    public class LockoutEventItem
    {
        public DateTime TimeCreated { get; set; }
        public int EventId { get; set; }
        public string CallerComputer { get; set; }
        public string SourceIp { get; set; }
        public string LogonType { get; set; }
        public string StatusOrCode { get; set; }
        public string UnlockedBy { get; set; }
        public string DomainController { get; set; }
        public long RecordId { get; set; }
    }

    public class CallerComputerItem
    {
        public string ComputerName { get; set; }
        public int EventCount { get; set; }
        public DateTime? LatestEvent { get; set; }
        public string EventTypes { get; set; }

        public override string ToString()
        {
            string timeStr = LatestEvent.HasValue ? LatestEvent.Value.ToString("yyyy-MM-dd HH:mm:ss") : "No timestamp";
            return string.Format("{0}   |   {1} event(s)   |   Latest: {2}", ComputerName, EventCount, timeStr);
        }
    }

    public class QUserSessionItem
    {
        public string UserName { get; set; }
        public string SessionName { get; set; }
        public string SessionId { get; set; }
        public string State { get; set; }
        public string IdleTime { get; set; }
        public string LogonTime { get; set; }
        public bool IsTargetUser { get; set; }
    }

    public class MainForm : Form
    {
        private List<UserRecord> _currentLockedUsers = new List<UserRecord>();
        private List<UserRecord> _historicalUsers = new List<UserRecord>();
        private List<string> _discoveredDCs = new List<string>();
        private UserRecord _selectedUser = null;
        private string _selectedComputer = null;
        private QUserSessionItem _selectedSession = null;

        // UI Controls - Column 1: Accounts
        private ListBox _lstCurrentAccounts;
        private ListBox _lstHistoricalAccounts;
        private Button _btnUnlock;
        private RichTextBox _rtbAccountDetails;
        private Button _btnCopyAccount;
        private Button _btnCopyTicket;
        private Button _btnRefreshLockouts;

        // UI Controls - Column 2: Caller Computers
        private ListBox _lstCallerComputers;
        private RichTextBox _rtbComputerDetails;
        private Button _btnRefreshComputer;
        private Button _btnCopyComputer;
        private Button _btnRebootComputer;

        // UI Controls - Column 3: Current Sessions
        private ListView _lvSessions;
        private Button _btnRefreshSessions;
        private Button _btnLogoffUser;
        private Button _btnResetPassword;

        // Status Strip
        private ToolStripStatusLabel _statusLabel;
        private ToolStripStatusLabel _countsLabel;
        private ToolStripStatusLabel _domainInfoLabel;
        private ToolStripProgressBar _progressBar;

        // Theme Support
        private bool _isDarkMode = false;
        private Button _btnThemeToggle;
        private Panel _headerPanel;
        private Label _lblTitle;
        private Label _lblSub;
        private GroupBox _grpAccounts;
        private GroupBox _grpComputers;
        private GroupBox _grpSessions;
        private StatusStrip _statusStrip;
        private ToolTip _toolTip;

        public MainForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            _toolTip = new ToolTip();
            this.Text = "Account Lockout Helper & Root Cause Investigator";
            this.Size = new Size(1680, 960);
            this.MinimumSize = new Size(1280, 760);
            this.WindowState = FormWindowState.Maximized;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = new Font("Segoe UI", 9.5F, FontStyle.Regular, GraphicsUnit.Point);
            this.BackColor = Color.FromArgb(243, 246, 250);
            this.KeyPreview = true;

            // -------------------------------------------------------------
            // Main Vertical Layout (Header, 3-Column Working Area, Status Bar)
            // -------------------------------------------------------------
            TableLayoutPanel mainLayout = new TableLayoutPanel();
            mainLayout.Dock = DockStyle.Fill;
            mainLayout.ColumnCount = 1;
            mainLayout.RowCount = 3;
            mainLayout.Padding = new Padding(10);
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 68F));  // Header
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F)); // 3 Columns
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32F));  // Status Bar
            this.Controls.Add(mainLayout);

            // -------------------------------------------------------------
            // Header
            // -------------------------------------------------------------
            Panel headerPanel = new Panel();
            headerPanel.Dock = DockStyle.Fill;
            headerPanel.BackColor = Color.White;
            headerPanel.BorderStyle = BorderStyle.FixedSingle;

            Label lblTitle = new Label();
            lblTitle.Text = "Account Lockout Helper";
            lblTitle.Font = new Font("Segoe UI", 16F, FontStyle.Bold);
            lblTitle.ForeColor = Color.FromArgb(15, 23, 42);
            lblTitle.AutoSize = true;
            lblTitle.Location = new Point(12, 6);

            Label lblSub = new Label();
            lblSub.Text = "Investigate currently locked-out accounts, review caller computers, inspect remote sessions via QUSER, and unlock accounts / reboot PCs.";
            lblSub.Font = new Font("Segoe UI", 9F);
            lblSub.ForeColor = Color.FromArgb(100, 116, 139);
            lblSub.AutoSize = true;
            lblSub.Location = new Point(14, 38);

            Button btnQuickRefresh = new Button();
            btnQuickRefresh.Text = "Refresh Forensics (F5)";
            btnQuickRefresh.Size = new Size(180, 34);
            btnQuickRefresh.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnQuickRefresh.Location = new Point(headerPanel.Width - 195, 16);
            btnQuickRefresh.BackColor = Color.FromArgb(37, 99, 235);
            btnQuickRefresh.ForeColor = Color.White;
            btnQuickRefresh.FlatStyle = FlatStyle.Flat;
            btnQuickRefresh.FlatAppearance.BorderSize = 0;
            btnQuickRefresh.Font = new Font("Segoe UI Semibold", 9F);
            btnQuickRefresh.Cursor = Cursors.Hand;
            btnQuickRefresh.Click += (s, e) => StartRefreshAsync();
            _headerPanel = headerPanel;
            _lblTitle = lblTitle;
            _lblSub = lblSub;

            _btnThemeToggle = new Button();
            _btnThemeToggle.Text = "Dark Mode";
            _btnThemeToggle.Size = new Size(130, 34);
            _btnThemeToggle.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnThemeToggle.Location = new Point(headerPanel.Width - 340, 16);
            _btnThemeToggle.BackColor = Color.FromArgb(241, 245, 249);
            _btnThemeToggle.ForeColor = Color.FromArgb(15, 23, 42);
            _btnThemeToggle.FlatStyle = FlatStyle.Flat;
            _btnThemeToggle.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
            _btnThemeToggle.Font = new Font("Segoe UI Semibold", 9F);
            _btnThemeToggle.Cursor = Cursors.Hand;
            _btnThemeToggle.Click += (s, e) => ToggleDarkMode();
            _toolTip.SetToolTip(_btnThemeToggle, "Toggle between Dark Mode and Light Mode for server rooms and low-light environments.");

            headerPanel.Controls.Add(lblTitle);
            headerPanel.Controls.Add(lblSub);
            headerPanel.Controls.Add(_btnThemeToggle);
            headerPanel.Controls.Add(btnQuickRefresh);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            // -------------------------------------------------------------
            // 3-Column Working Area (Matches User's Original Architecture)
            // Column 1: 32% (Accounts), Column 2: 32% (Caller Computers), Column 3: 36% (Sessions)
            // -------------------------------------------------------------
            TableLayoutPanel workLayout = new TableLayoutPanel();
            workLayout.Dock = DockStyle.Fill;
            workLayout.ColumnCount = 3;
            workLayout.RowCount = 1;
            workLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32F));
            workLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32F));
            workLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 36F));
            workLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            workLayout.Padding = new Padding(0, 6, 0, 6);
            mainLayout.Controls.Add(workLayout, 0, 1);

            // =============================================================
            // COLUMN 1: ACCOUNT LOCKOUT HISTORY
            // =============================================================
            GroupBox grpAccounts = new GroupBox();
            _grpAccounts = grpAccounts;
            grpAccounts.Text = " Account Lockout History ";
            grpAccounts.Dock = DockStyle.Fill;
            grpAccounts.Font = new Font("Segoe UI Semibold", 9.5F);
            grpAccounts.BackColor = Color.White;
            grpAccounts.Padding = new Padding(8);

            TableLayoutPanel col1Layout = new TableLayoutPanel();
            col1Layout.Dock = DockStyle.Fill;
            col1Layout.ColumnCount = 1;
            col1Layout.RowCount = 6;
            col1Layout.RowStyles.Add(new RowStyle(SizeType.Percent, 22F)); // Currently Locked List
            col1Layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F)); // Unlock Button
            col1Layout.RowStyles.Add(new RowStyle(SizeType.Percent, 20F)); // Previously Locked List
            col1Layout.RowStyles.Add(new RowStyle(SizeType.Percent, 58F)); // Account Details
            col1Layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F)); // Reset Password Button
            col1Layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42F)); // Bottom Action Buttons
            col1Layout.Padding = new Padding(4);

            // 1. Currently Locked Out List
            GroupBox grpCurrent = new GroupBox();
            grpCurrent.Text = "Currently Locked Out - Active Users Only";
            grpCurrent.Dock = DockStyle.Fill;
            grpCurrent.Font = new Font("Segoe UI", 9F);
            _lstCurrentAccounts = new ListBox();
            _lstCurrentAccounts.Dock = DockStyle.Fill;
            _lstCurrentAccounts.Font = new Font("Segoe UI", 9.5F);
            _lstCurrentAccounts.IntegralHeight = false;
            _lstCurrentAccounts.SelectedIndexChanged += AccountSelectionChanged;
            grpCurrent.Controls.Add(_lstCurrentAccounts);
            col1Layout.Controls.Add(grpCurrent, 0, 0);

            // 2. Unlock Button
            _btnUnlock = new Button();
            _btnUnlock.Text = "UNLOCK SELECTED USER";
            _btnUnlock.Dock = DockStyle.Fill;
            _btnUnlock.BackColor = Color.FromArgb(220, 252, 231); // emerald-100
            _btnUnlock.ForeColor = Color.FromArgb(22, 101, 52);   // emerald-800
            _btnUnlock.FlatStyle = FlatStyle.Flat;
            _btnUnlock.FlatAppearance.BorderColor = Color.FromArgb(134, 239, 172);
            _btnUnlock.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            _btnUnlock.Enabled = false;
            _btnUnlock.Cursor = Cursors.Hand;
            _btnUnlock.Click += UnlockAccountClick;
            col1Layout.Controls.Add(_btnUnlock, 0, 1);

            // 3. Previously Locked Out List
            GroupBox grpHistorical = new GroupBox();
            grpHistorical.Text = "Previously Locked Out - Selectable for Investigation";
            grpHistorical.Dock = DockStyle.Fill;
            grpHistorical.Font = new Font("Segoe UI", 9F);
            _lstHistoricalAccounts = new ListBox();
            _lstHistoricalAccounts.Dock = DockStyle.Fill;
            _lstHistoricalAccounts.Font = new Font("Segoe UI", 9F);
            _lstHistoricalAccounts.IntegralHeight = false;
            _lstHistoricalAccounts.SelectedIndexChanged += AccountSelectionChanged;
            grpHistorical.Controls.Add(_lstHistoricalAccounts);
            col1Layout.Controls.Add(grpHistorical, 0, 2);

            // 4. Account Details Text
            GroupBox grpAccDetails = new GroupBox();
            grpAccDetails.Text = "Account Details & Root Cause Forensics";
            grpAccDetails.Dock = DockStyle.Fill;
            grpAccDetails.Font = new Font("Segoe UI", 9F);
            _rtbAccountDetails = new RichTextBox();
            _rtbAccountDetails.Dock = DockStyle.Fill;
            _rtbAccountDetails.ReadOnly = true;
            _rtbAccountDetails.BackColor = Color.FromArgb(250, 251, 253);
            _rtbAccountDetails.Font = new Font("Segoe UI", 9F);
            _rtbAccountDetails.ScrollBars = RichTextBoxScrollBars.Vertical;
            _rtbAccountDetails.WordWrap = true;
            _rtbAccountDetails.Text = "Select an account to view Active Directory attributes, lockout evidence, and root cause diagnosis.";
            grpAccDetails.Controls.Add(_rtbAccountDetails);
            col1Layout.Controls.Add(grpAccDetails, 0, 3);

            // 5. Reset Password Button
            _btnResetPassword = new Button();
            _btnResetPassword.Text = "RESET USER PASSWORD";
            _btnResetPassword.Dock = DockStyle.Fill;
            _btnResetPassword.BackColor = Color.FromArgb(241, 245, 249);
            _btnResetPassword.ForeColor = Color.FromArgb(15, 23, 42);
            _btnResetPassword.FlatStyle = FlatStyle.Flat;
            _btnResetPassword.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
            _btnResetPassword.Font = new Font("Segoe UI Semibold", 9F);
            _btnResetPassword.Enabled = false;
            _btnResetPassword.Cursor = Cursors.Hand;
            _btnResetPassword.Click += ResetPasswordClick;
            col1Layout.Controls.Add(_btnResetPassword, 0, 4);

            // 6. Action buttons (Copy Account, Copy Ticket, Refresh)
            FlowLayoutPanel accBtnLayout = new FlowLayoutPanel();
            accBtnLayout.Dock = DockStyle.Fill;
            accBtnLayout.FlowDirection = FlowDirection.LeftToRight;
            accBtnLayout.WrapContents = false;

            _btnCopyAccount = new Button();
            _btnCopyAccount.Text = "Copy Account Details";
            _btnCopyAccount.Size = new Size(150, 34);
            _btnCopyAccount.BackColor = Color.FromArgb(248, 250, 252);
            _btnCopyAccount.FlatStyle = FlatStyle.Flat;
            _btnCopyAccount.FlatAppearance.BorderColor = Color.FromArgb(220, 227, 236);
            _btnCopyAccount.Font = new Font("Segoe UI", 8.5F);
            _btnCopyAccount.Cursor = Cursors.Hand;
            _btnCopyAccount.Click += (s, e) => CopyToClipboard(_rtbAccountDetails.Text, "Account details copied to clipboard.");

            _btnCopyTicket = new Button();
            _btnCopyTicket.Text = "Copy Full Ticket";
            _btnCopyTicket.Size = new Size(130, 34);
            _btnCopyTicket.BackColor = Color.FromArgb(248, 250, 252);
            _btnCopyTicket.FlatStyle = FlatStyle.Flat;
            _btnCopyTicket.FlatAppearance.BorderColor = Color.FromArgb(220, 227, 236);
            _btnCopyTicket.Font = new Font("Segoe UI", 8.5F);
            _btnCopyTicket.Cursor = Cursors.Hand;
            _btnCopyTicket.Click += (s, e) => CopyFullTicket();

            _btnRefreshLockouts = new Button();
            _btnRefreshLockouts.Text = "Refresh Forensic Data";
            _btnRefreshLockouts.Size = new Size(160, 34);
            _btnRefreshLockouts.BackColor = Color.FromArgb(37, 99, 235);
            _btnRefreshLockouts.ForeColor = Color.White;
            _btnRefreshLockouts.FlatStyle = FlatStyle.Flat;
            _btnRefreshLockouts.FlatAppearance.BorderSize = 0;
            _btnRefreshLockouts.Font = new Font("Segoe UI Semibold", 8.5F);
            _btnRefreshLockouts.Cursor = Cursors.Hand;
            _btnRefreshLockouts.Click += (s, e) => StartRefreshAsync();
            _toolTip.SetToolTip(_btnRefreshLockouts, "Queries Active Directory for currently locked accounts and scans Domain Controller Security logs for Event 4740 forensic records.");

            accBtnLayout.Controls.Add(_btnCopyAccount);
            accBtnLayout.Controls.Add(_btnCopyTicket);
            accBtnLayout.Controls.Add(_btnRefreshLockouts);
            col1Layout.Controls.Add(accBtnLayout, 0, 5);

            grpAccounts.Controls.Add(col1Layout);
            workLayout.Controls.Add(grpAccounts, 0, 0);

            // =============================================================
            // COLUMN 2: CALLER COMPUTERS (PROMINENT LIST + COMPUTER DETAILS)
            // =============================================================
            GroupBox grpComputers = new GroupBox();
            _grpComputers = grpComputers;
            grpComputers.Text = " Caller Computers ";
            grpComputers.Dock = DockStyle.Fill;
            grpComputers.Font = new Font("Segoe UI Semibold", 9.5F);
            grpComputers.BackColor = Color.White;
            grpComputers.Padding = new Padding(8);

            TableLayoutPanel col2Layout = new TableLayoutPanel();
            col2Layout.Dock = DockStyle.Fill;
            col2Layout.ColumnCount = 1;
            col2Layout.RowCount = 4;
            col2Layout.RowStyles.Add(new RowStyle(SizeType.Percent, 35F)); // Caller Computer List (PROMINENT!)
            col2Layout.RowStyles.Add(new RowStyle(SizeType.Percent, 65F)); // Computer Details
            col2Layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42F)); // Actions (Refresh, Copy)
            col2Layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42F)); // Reboot Button
            col2Layout.Padding = new Padding(4);

            // 1. Caller Computers ListBox
            _lstCallerComputers = new ListBox();
            _lstCallerComputers.Dock = DockStyle.Fill;
            _lstCallerComputers.Font = new Font("Segoe UI", 10F);
            _lstCallerComputers.IntegralHeight = false;
            _lstCallerComputers.HorizontalScrollbar = true;
            _lstCallerComputers.SelectedIndexChanged += CallerSelectionChanged;
            col2Layout.Controls.Add(_lstCallerComputers, 0, 0);

            // 2. Computer Details
            GroupBox grpCompDetails = new GroupBox();
            grpCompDetails.Text = "Computer Details & Active Directory Record";
            grpCompDetails.Dock = DockStyle.Fill;
            grpCompDetails.Font = new Font("Segoe UI", 9F);
            _rtbComputerDetails = new RichTextBox();
            _rtbComputerDetails.Dock = DockStyle.Fill;
            _rtbComputerDetails.ReadOnly = true;
            _rtbComputerDetails.BackColor = Color.FromArgb(250, 251, 253);
            _rtbComputerDetails.Font = new Font("Segoe UI", 9F);
            _rtbComputerDetails.ScrollBars = RichTextBoxScrollBars.Vertical;
            _rtbComputerDetails.WordWrap = true;
            _rtbComputerDetails.Text = "Select a caller computer above to inspect its Active Directory record and session summary.";
            grpCompDetails.Controls.Add(_rtbComputerDetails);
            col2Layout.Controls.Add(grpCompDetails, 0, 1);

            // 3. Computer Action buttons
            FlowLayoutPanel compBtnLayout = new FlowLayoutPanel();
            compBtnLayout.Dock = DockStyle.Fill;
            compBtnLayout.FlowDirection = FlowDirection.LeftToRight;
            compBtnLayout.WrapContents = false;

            _btnRefreshComputer = new Button();
            _btnRefreshComputer.Text = "Refresh Computer";
            _btnRefreshComputer.Size = new Size(150, 34);
            _btnRefreshComputer.BackColor = Color.FromArgb(248, 250, 252);
            _btnRefreshComputer.FlatStyle = FlatStyle.Flat;
            _btnRefreshComputer.FlatAppearance.BorderColor = Color.FromArgb(220, 227, 236);
            _btnRefreshComputer.Font = new Font("Segoe UI", 8.5F);
            _btnRefreshComputer.Cursor = Cursors.Hand;
            _btnRefreshComputer.Click += (s, e) => CallerSelectionChanged(null, null);

            _btnCopyComputer = new Button();
            _btnCopyComputer.Text = "Copy Computer Details";
            _btnCopyComputer.Size = new Size(160, 34);
            _btnCopyComputer.BackColor = Color.FromArgb(248, 250, 252);
            _btnCopyComputer.FlatStyle = FlatStyle.Flat;
            _btnCopyComputer.FlatAppearance.BorderColor = Color.FromArgb(220, 227, 236);
            _btnCopyComputer.Font = new Font("Segoe UI", 8.5F);
            _btnCopyComputer.Cursor = Cursors.Hand;
            _btnCopyComputer.Click += (s, e) => CopyToClipboard(_rtbComputerDetails.Text, "Computer details copied to clipboard.");

            compBtnLayout.Controls.Add(_btnRefreshComputer);
            compBtnLayout.Controls.Add(_btnCopyComputer);
            col2Layout.Controls.Add(compBtnLayout, 0, 2);

            // 4. Remote Reboot Button
            _btnRebootComputer = new Button();
            _btnRebootComputer.Text = "REBOOT SELECTED COMPUTER";
            _btnRebootComputer.Dock = DockStyle.Fill;
            _btnRebootComputer.BackColor = Color.FromArgb(225, 29, 72); // rose-600
            _btnRebootComputer.ForeColor = Color.White;
            _btnRebootComputer.FlatStyle = FlatStyle.Flat;
            _btnRebootComputer.FlatAppearance.BorderSize = 0;
            _btnRebootComputer.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            _btnRebootComputer.Enabled = false;
            _btnRebootComputer.Cursor = Cursors.Hand;
            _btnRebootComputer.Click += RebootComputerClick;
            col2Layout.Controls.Add(_btnRebootComputer, 0, 3);

            grpComputers.Controls.Add(col2Layout);
            workLayout.Controls.Add(grpComputers, 1, 0);

            // =============================================================
            // COLUMN 3: CURRENT SESSIONS (QUSER)
            // =============================================================
            GroupBox grpSessions = new GroupBox();
            _grpSessions = grpSessions;
            grpSessions.Text = " Current Sessions on Selected Computer (QUSER) ";
            grpSessions.Dock = DockStyle.Fill;
            grpSessions.Font = new Font("Segoe UI Semibold", 9.5F);
            grpSessions.BackColor = Color.White;
            grpSessions.Padding = new Padding(8);

            TableLayoutPanel col3Layout = new TableLayoutPanel();
            col3Layout.Dock = DockStyle.Fill;
            col3Layout.ColumnCount = 1;
            col3Layout.RowCount = 3;
            col3Layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F)); // ListView
            col3Layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46F));  // Buttons
            col3Layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46F));  // Explanatory Help Label
            col3Layout.Padding = new Padding(4);

            _lvSessions = new ListView();
            _lvSessions.Dock = DockStyle.Fill;
            _lvSessions.View = View.Details;
            _lvSessions.FullRowSelect = true;
            _lvSessions.GridLines = true;
            _lvSessions.MultiSelect = false;
            _lvSessions.HideSelection = false;
            _lvSessions.Font = new Font("Segoe UI", 9.5F);
            _lvSessions.Columns.Add("User", 150);
            _lvSessions.Columns.Add("ID", 50);
            _lvSessions.Columns.Add("State", 80);
            _lvSessions.Columns.Add("Idle", 80);
            _lvSessions.Columns.Add("Logon Time", 160);
            _lvSessions.Columns.Add("Target", 80);
            _lvSessions.SelectedIndexChanged += SessionSelectionChanged;
            col3Layout.Controls.Add(_lvSessions, 0, 0);

            FlowLayoutPanel sessBtnLayout = new FlowLayoutPanel();
            sessBtnLayout.Dock = DockStyle.Fill;
            sessBtnLayout.FlowDirection = FlowDirection.LeftToRight;
            sessBtnLayout.WrapContents = false;

            _btnRefreshSessions = new Button();
            _btnRefreshSessions.Text = "Refresh Sessions";
            _btnRefreshSessions.Size = new Size(150, 36);
            _btnRefreshSessions.BackColor = Color.FromArgb(248, 250, 252);
            _btnRefreshSessions.FlatStyle = FlatStyle.Flat;
            _btnRefreshSessions.FlatAppearance.BorderColor = Color.FromArgb(220, 227, 236);
            _btnRefreshSessions.Font = new Font("Segoe UI Semibold", 9F);
            _btnRefreshSessions.Cursor = Cursors.Hand;
            _btnRefreshSessions.Click += (s, e) => QueryQUserAsync(_selectedComputer);

            _btnLogoffUser = new Button();
            _btnLogoffUser.Text = "LOG OFF TARGET USER";
            _btnLogoffUser.Size = new Size(185, 36);
            _btnLogoffUser.BackColor = Color.FromArgb(185, 28, 28); // red-700
            _btnLogoffUser.ForeColor = Color.White;
            _btnLogoffUser.FlatStyle = FlatStyle.Flat;
            _btnLogoffUser.FlatAppearance.BorderSize = 0;
            _btnLogoffUser.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            _btnLogoffUser.Enabled = false;
            _btnLogoffUser.Cursor = Cursors.Hand;
            _btnLogoffUser.Click += LogoffUserClick;

            sessBtnLayout.Controls.Add(_btnRefreshSessions);
            sessBtnLayout.Controls.Add(_btnLogoffUser);
            col3Layout.Controls.Add(sessBtnLayout, 0, 1);

            Label lblSessionHelp = new Label();
            lblSessionHelp.Dock = DockStyle.Fill;
            lblSessionHelp.Text = "The session list shows all users reported on the selected computer. For safety, remote logoff is enabled only for the investigated account when its session is Active or Disconnected.";
            lblSessionHelp.Font = new Font("Segoe UI", 8.5F);
            lblSessionHelp.ForeColor = Color.FromArgb(100, 116, 139);
            lblSessionHelp.TextAlign = ContentAlignment.MiddleLeft;
            col3Layout.Controls.Add(lblSessionHelp, 0, 2);

            grpSessions.Controls.Add(col3Layout);
            workLayout.Controls.Add(grpSessions, 2, 0);

            // =============================================================
            // BOTTOM STATUS STRIP
            // =============================================================
            StatusStrip statusStrip = new StatusStrip();
            _statusStrip = statusStrip;
            statusStrip.Dock = DockStyle.Fill;
            statusStrip.BackColor = Color.FromArgb(232, 238, 246);
            statusStrip.Font = new Font("Segoe UI", 9F);

            _statusLabel = new ToolStripStatusLabel();
            _statusLabel.Spring = true;
            _statusLabel.TextAlign = ContentAlignment.MiddleLeft;
            _statusLabel.Text = "Ready. Discovered accounts will load automatically.";

            _progressBar = new ToolStripProgressBar();
            _progressBar.Size = new Size(140, 16);
            _progressBar.Style = ProgressBarStyle.Marquee;
            _progressBar.Visible = false;

            _countsLabel = new ToolStripStatusLabel();
            _countsLabel.Text = "Locked: 0  |  Historical: 0";
            _countsLabel.ForeColor = Color.FromArgb(30, 41, 59);

            _domainInfoLabel = new ToolStripStatusLabel();
            _domainInfoLabel.Text = "Domain: Detecting...";
            _domainInfoLabel.ForeColor = Color.FromArgb(71, 85, 105);

            statusStrip.Items.Add(_statusLabel);
            statusStrip.Items.Add(_progressBar);
            statusStrip.Items.Add(_countsLabel);
            statusStrip.Items.Add(_domainInfoLabel);
            mainLayout.Controls.Add(statusStrip, 0, 2);

            this.Shown += (s, e) => StartRefreshAsync();
        }

        // -------------------------------------------------------------
        // DARK MODE THEME TOGGLE & CONTROL STYLING
        // Reduces eye strain for admins working in server rooms & dark offices
        // -------------------------------------------------------------
        private void ToggleDarkMode()
        {
            _isDarkMode = !_isDarkMode;
            ApplyTheme(_isDarkMode);
        }

        private void ApplyTheme(bool dark)
        {
            if (_btnThemeToggle != null)
            {
                _btnThemeToggle.Text = dark ? "Light Mode" : "Dark Mode";
            }

            Color bg = dark ? Color.FromArgb(15, 23, 42) : Color.FromArgb(243, 246, 250);
            Color surface = dark ? Color.FromArgb(30, 41, 59) : Color.White;
            Color textPrimary = dark ? Color.FromArgb(241, 245, 249) : Color.FromArgb(15, 23, 42);
            Color textSecondary = dark ? Color.FromArgb(148, 163, 184) : Color.FromArgb(100, 116, 139);
            Color inputBg = dark ? Color.FromArgb(15, 23, 42) : Color.White;
            Color btnBg = dark ? Color.FromArgb(51, 65, 85) : Color.FromArgb(248, 250, 252);
            Color btnBorder = dark ? Color.FromArgb(71, 85, 105) : Color.FromArgb(220, 227, 236);

            this.BackColor = bg;
            ApplyThemeRecursive(this, dark, bg, surface, textPrimary, textSecondary, inputBg, btnBg, btnBorder);

            if (_statusStrip != null)
            {
                _statusStrip.BackColor = dark ? Color.FromArgb(15, 23, 42) : Color.FromArgb(232, 238, 246);
            }
            if (_statusLabel != null) _statusLabel.ForeColor = textSecondary;
            if (_countsLabel != null) _countsLabel.ForeColor = textPrimary;
            if (_domainInfoLabel != null) _domainInfoLabel.ForeColor = textSecondary;
        }

        private void ApplyThemeRecursive(Control parent, bool dark, Color bg, Color surface, Color textPrimary, Color textSecondary, Color inputBg, Color btnBg, Color btnBorder)
        {
            if (parent == null) return;

            foreach (Control ctrl in parent.Controls)
            {
                if (ctrl is GroupBox)
                {
                    ctrl.BackColor = surface;
                    ctrl.ForeColor = textPrimary;
                }
                else if (ctrl is ListBox || ctrl is RichTextBox || ctrl is TextBox)
                {
                    ctrl.BackColor = inputBg;
                    ctrl.ForeColor = textPrimary;
                }
                else if (ctrl is ListView)
                {
                    ctrl.BackColor = inputBg;
                    ctrl.ForeColor = textPrimary;
                }
                else if (ctrl is Label)
                {
                    if (ctrl == _lblTitle) ctrl.ForeColor = textPrimary;
                    else if (ctrl == _lblSub) ctrl.ForeColor = textSecondary;
                    else ctrl.ForeColor = textSecondary;
                }
                else if (ctrl is Button)
                {
                    Button b = (Button)ctrl;
                    if (b == _btnUnlock)
                    {
                        b.BackColor = dark ? Color.FromArgb(6, 78, 59) : Color.FromArgb(220, 252, 231);
                        b.ForeColor = dark ? Color.FromArgb(167, 243, 208) : Color.FromArgb(22, 101, 52);
                    }
                    else if (b == _btnRebootComputer || b == _btnLogoffUser)
                    {
                        b.BackColor = dark ? Color.FromArgb(127, 29, 29) : Color.FromArgb(185, 28, 28);
                        b.ForeColor = Color.White;
                    }
                    else if (b == _btnRefreshLockouts)
                    {
                        b.BackColor = Color.FromArgb(37, 99, 235);
                        b.ForeColor = Color.White;
                    }
                    else
                    {
                        b.BackColor = btnBg;
                        b.ForeColor = textPrimary;
                        b.FlatAppearance.BorderColor = btnBorder;
                    }
                }
                else if (ctrl is Panel || ctrl is TableLayoutPanel || ctrl is FlowLayoutPanel)
                {
                    ctrl.BackColor = (ctrl == _headerPanel) ? surface : bg;
                }

                if (ctrl.HasChildren)
                {
                    ApplyThemeRecursive(ctrl, dark, bg, surface, textPrimary, textSecondary, inputBg, btnBg, btnBorder);
                }
            }
        }

        private static long GetInt64FromLargeInt(object val)
        {
            if (val == null) return 0;
            if (val is long) return (long)val;
            if (val is int) return (int)val;
            if (val is double) return (long)(double)val;
            try
            {
                Type t = val.GetType();
                int high = (int)t.InvokeMember("HighPart", BindingFlags.GetProperty, null, val, null);
                int low = (int)t.InvokeMember("LowPart", BindingFlags.GetProperty, null, val, null);
                return ((long)high << 32) | (uint)low;
            }
            catch
            {
                long parsed;
                if (long.TryParse(val.ToString(), out parsed)) return parsed;
                return 0;
            }
        }

        // -------------------------------------------------------------
        // ACTIVE DIRECTORY DISCOVERY & EVENT LOG SCANNING
        // (CRITICAL: EXCLUDES DISABLED USER ACCOUNTS)
        // -------------------------------------------------------------
        private void StartRefreshAsync()
        {
            _btnRefreshLockouts.Enabled = false;
            _progressBar.Visible = true;
            _statusLabel.Text = "Discovering Active Directory Domain Controllers and active locked users...";

            ThreadPool.QueueUserWorkItem(state =>
            {
                List<string> dcs = new List<string>();
                List<UserRecord> lockedUsers = new List<UserRecord>();
                List<UserRecord> historicalUsers = new List<UserRecord>();
                Dictionary<string, bool> disabledAccountCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
                string domainName = "Unknown";
                string errorMsg = null;

                try
                {
                    // 1. Discover Domain Controllers
                    try
                    {
                        Domain currentDomain = Domain.GetCurrentDomain();
                        domainName = currentDomain.Name;
                        foreach (DomainController dc in currentDomain.DomainControllers)
                        {
                            dcs.Add(dc.Name);
                        }
                    }
                    catch
                    {
                        string logonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
                        if (!string.IsNullOrEmpty(logonServer))
                        {
                            dcs.Add(logonServer.TrimStart('\\'));
                        }
                        string userDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                        if (!string.IsNullOrEmpty(userDomain)) domainName = userDomain;
                    }

                    if (dcs.Count == 0)
                    {
                        errorMsg = "No Active Directory Domain Controllers could be contacted. Verify network or VPN connection.";
                    }
                    else
                    {

                        // 2. Query Currently Locked Accounts via LDAP
                        // CRITICAL: Check IsAccountLocked so accounts whose lockout duration expired are NOT marked as currently locked!
                        try
                        {
                            using (DirectorySearcher searcher = new DirectorySearcher())
                            {
                                searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lockoutTime>=1))";
                                searcher.PageSize = 500;
                                searcher.PropertiesToLoad.AddRange(new string[] {
                                    "samaccountname", "displayname", "userprincipalname", "mail",
                                    "department", "title", "useraccountcontrol", "badpwdcount",
                                    "lastbadpasswordattempt", "pwdlastset", "lockouttime",
                                    "lastlogontimestamp", "accountexpires", "memberof", "msds-resultantpso"
                                });

                                SearchResultCollection results = searcher.FindAll();
                                foreach (SearchResult res in results)
                                {
                                    string sam = res.Properties["samaccountname"].Count > 0 ? (string)res.Properties["samaccountname"][0] : "";
                                    string disp = res.Properties["displayname"].Count > 0 ? (string)res.Properties["displayname"][0] : sam;
                                    string upn = res.Properties["userprincipalname"].Count > 0 ? (string)res.Properties["userprincipalname"][0] : "";
                                    string email = res.Properties["mail"].Count > 0 ? (string)res.Properties["mail"][0] : "";
                                    string dept = res.Properties["department"].Count > 0 ? (string)res.Properties["department"][0] : "";
                                    string title = res.Properties["title"].Count > 0 ? (string)res.Properties["title"][0] : "";

                                    int uac = res.Properties["useraccountcontrol"].Count > 0 ? Convert.ToInt32(res.Properties["useraccountcontrol"][0]) : 0;
                                    bool isDisabled = (uac & 2) != 0;
                                    if (isDisabled) continue; // Safety check: skip disabled accounts!

                                    int badPwd = res.Properties["badpwdcount"].Count > 0 ? Convert.ToInt32(res.Properties["badpwdcount"][0]) : 0;

                                    if (!string.IsNullOrEmpty(sam))
                                    {
                                        disabledAccountCache[sam] = false;

                                        // CRITICAL: Active Directory Service Interfaces check to verify if the account is ACTUALLY locked right now
                                        bool isActivelyLocked = false;
                                        try
                                        {
                                            DirectoryEntry de = res.GetDirectoryEntry();
                                            isActivelyLocked = (bool)de.InvokeGet("IsAccountLocked");
                                        }
                                        catch
                                        {
                                            try
                                            {
                                                using (PrincipalContext pctx = new PrincipalContext(ContextType.Domain, domainName))
                                                {
                                                    using (UserPrincipal up = UserPrincipal.FindByIdentity(pctx, sam))
                                                    {
                                                        if (up != null) isActivelyLocked = up.IsAccountLockedOut();
                                                    }
                                                }
                                            }
                                            catch { isActivelyLocked = false; }
                                        }

                                        UserRecord uRec = new UserRecord
                                        {
                                            SamAccountName = sam,
                                            DisplayName = disp,
                                            UserPrincipalName = upn,
                                            EmailAddress = email,
                                            Department = dept,
                                            Title = title,
                                            Enabled = true,
                                            IsCurrentlyLocked = isActivelyLocked,
                                            BadPasswordCount = badPwd,
                                            PasswordNeverExpires = (uac & 0x10000) != 0
                                        };

                                        if (res.Properties.Contains("pwdlastset") && res.Properties["pwdlastset"].Count > 0)
                                        {
                                            long ft = GetInt64FromLargeInt(res.Properties["pwdlastset"][0]);
                                            if (ft == 0) uRec.MustChangePasswordAtNextLogon = true;
                                            else { try { uRec.PasswordLastSet = DateTime.FromFileTime(ft); } catch { } }
                                        }
                                        if (res.Properties.Contains("lastbadpasswordattempt") && res.Properties["lastbadpasswordattempt"].Count > 0)
                                        {
                                            long ft = GetInt64FromLargeInt(res.Properties["lastbadpasswordattempt"][0]);
                                            if (ft > 0) { try { uRec.LastBadPasswordAttempt = DateTime.FromFileTime(ft); } catch { } }
                                        }
                                        if (res.Properties.Contains("lastlogontimestamp") && res.Properties["lastlogontimestamp"].Count > 0)
                                        {
                                            long ft = GetInt64FromLargeInt(res.Properties["lastlogontimestamp"][0]);
                                            if (ft > 0) { try { uRec.LastLogonTimestamp = DateTime.FromFileTime(ft); } catch { } }
                                        }
                                        if (res.Properties.Contains("accountexpires") && res.Properties["accountexpires"].Count > 0)
                                        {
                                            long ft = GetInt64FromLargeInt(res.Properties["accountexpires"][0]);
                                            if (ft > 0 && ft != 9223372036854775807L && ft != 0x7FFFFFFFFFFFFFFFL) { try { uRec.AccountExpires = DateTime.FromFileTime(ft); } catch { } }
                                        }
                                        if (res.Properties.Contains("memberof"))
                                        {
                                            foreach (object grp in res.Properties["memberof"])
                                            {
                                                string grpStr = grp != null ? grp.ToString() : "";
                                                if (grpStr.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                                                {
                                                    int commaIdx = grpStr.IndexOf(',');
                                                    string grpName = commaIdx > 3 ? grpStr.Substring(3, commaIdx - 3) : grpStr.Substring(3);
                                                    uRec.MemberOfGroups.Add(grpName);
                                                }
                                            }
                                        }

                                        if (res.Properties.Contains("msds-resultantpso") && res.Properties["msds-resultantpso"].Count > 0)
                                        {
                                            string psoStr = res.Properties["msds-resultantpso"][0].ToString();
                                            if (psoStr.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                                            {
                                                int commaIdx = psoStr.IndexOf(',');
                                                uRec.ResultantPSO = commaIdx > 3 ? psoStr.Substring(3, commaIdx - 3) : psoStr.Substring(3);
                                            }
                                            else
                                            {
                                                uRec.ResultantPSO = psoStr;
                                            }
                                        }

                                        if (isActivelyLocked)
                                        {
                                            lockedUsers.Add(uRec);
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine("LDAP query error: " + ex.Message);
                        }

                        // 3. Scan Event 4740 (Account Lockout) across DCs
                        Dictionary<string, List<LockoutEventItem>> eventMap = new Dictionary<string, List<LockoutEventItem>>(StringComparer.OrdinalIgnoreCase);

                        foreach (string dc in dcs)
                        {
                            try
                            {
                                string query = "*[System[((EventID=4740 or EventID=4767)) and TimeCreated[timediff(@SystemTime) <= 7776000000]]]"; // 90 days
                                EventLogQuery elq = new EventLogQuery("Security", PathType.LogName, query);
                                elq.Session = new EventLogSession(dc);

                                using (EventLogReader reader = new EventLogReader(elq))
                                {
                                    EventRecord record;
                                    int count = 0;
                                    while ((record = reader.ReadEvent()) != null && count < 800)
                                    {
                                        count++;
                                        int eventId = record.Id;
                                        string rawUser = null;
                                        string caller = null;
                                        string unlockedBy = null;

                                        if (eventId == 4767)
                                        {
                                            // Event 4767: A user account was unlocked
                                            // Prop 0: TargetUserName, Prop 1: TargetDomainName, Prop 4: SubjectUserName, Prop 5: SubjectDomainName
                                            if (record.Properties.Count > 0 && record.Properties[0].Value != null)
                                                rawUser = record.Properties[0].Value.ToString();

                                            string subUser = (record.Properties.Count > 4 && record.Properties[4].Value != null) ? record.Properties[4].Value.ToString() : null;
                                            string subDomain = (record.Properties.Count > 5 && record.Properties[5].Value != null) ? record.Properties[5].Value.ToString() : null;
                                            if (!string.IsNullOrEmpty(subUser))
                                            {
                                                unlockedBy = !string.IsNullOrEmpty(subDomain) ? subDomain + "\\" + subUser : subUser;
                                            }
                                        }
                                        else
                                        {
                                            // Event 4740: A user account was locked out
                                            if (record.Properties.Count > 0 && record.Properties[0].Value != null)
                                                rawUser = record.Properties[0].Value.ToString();
                                            if (record.Properties.Count > 1 && record.Properties[1].Value != null)
                                                caller = record.Properties[1].Value.ToString();
                                        }

                                        if (!string.IsNullOrEmpty(rawUser))
                                        {
                                            string cleanUser = NormalizeAccount(rawUser);
                                            if (string.Equals(cleanUser, "SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                                                string.Equals(cleanUser, "ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase))
                                                continue;

                                            LockoutEventItem item = new LockoutEventItem
                                            {
                                                TimeCreated = record.TimeCreated ?? DateTime.Now,
                                                EventId = eventId,
                                                CallerComputer = !string.IsNullOrEmpty(caller) ? NormalizeComputer(caller) : null,
                                                UnlockedBy = unlockedBy,
                                                DomainController = dc,
                                                RecordId = record.RecordId ?? 0
                                            };

                                            if (!eventMap.ContainsKey(cleanUser))
                                                eventMap[cleanUser] = new List<LockoutEventItem>();
                                            eventMap[cleanUser].Add(item);
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine("DC Event log error on " + dc + ": " + ex.Message);
                            }
                        }

                        // Sort all event lists by TimeCreated descending so newest events appear first
                        foreach (var list in eventMap.Values)
                        {
                            list.Sort((a, b) => b.TimeCreated.CompareTo(a.TimeCreated));
                        }

                        // Attach events to currently locked users
                        HashSet<string> currentSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (UserRecord u in lockedUsers)
                        {
                            currentSet.Add(u.SamAccountName);
                            if (eventMap.ContainsKey(u.SamAccountName))
                            {
                                u.Events = eventMap[u.SamAccountName];
                                u.EventCount = u.Events.Count;
                                if (u.Events.Count > 0)
                                {
                                    u.LatestEventTime = u.Events[0].TimeCreated;
                                    LockoutEventItem latestLock = u.Events.Find(e => !string.IsNullOrEmpty(e.CallerComputer));
                                    if (latestLock != null)
                                    {
                                        u.LatestCaller = latestLock.CallerComputer;
                                        u.LatestDC = latestLock.DomainController;
                                    }
                                    else
                                    {
                                        u.LatestCaller = u.Events[0].CallerComputer ?? "";
                                        u.LatestDC = u.Events[0].DomainController;
                                    }
                                }
                            }
                        }

                        // Attach events to historical users (from LDAP expired lockouts)
                        HashSet<string> histSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (UserRecord u in historicalUsers)
                        {
                            histSet.Add(u.SamAccountName);
                            if (eventMap.ContainsKey(u.SamAccountName))
                            {
                                u.Events = eventMap[u.SamAccountName];
                                u.EventCount = u.Events.Count;
                                if (u.Events.Count > 0)
                                {
                                    u.LatestEventTime = u.Events[0].TimeCreated;
                                    LockoutEventItem latestLock = u.Events.Find(e => !string.IsNullOrEmpty(e.CallerComputer));
                                    if (latestLock != null)
                                    {
                                        u.LatestCaller = latestLock.CallerComputer;
                                        u.LatestDC = latestLock.DomainController;
                                    }
                                    else
                                    {
                                        u.LatestCaller = u.Events[0].CallerComputer ?? "";
                                        u.LatestDC = u.Events[0].DomainController;
                                    }
                                }
                            }
                        }

                        // Build historical list (users who had 4740 events but are not currently locked)
                        // CRITICAL: Filter out accounts that are currently disabled in Active Directory!
                        foreach (var kvp in eventMap)
                        {
                            string sam = kvp.Key;
                            if (currentSet.Contains(sam) || histSet.Contains(sam)) continue;

                            // Check if account is disabled in AD
                            bool isDisabled = false;
                            string histDisp = sam;
                            string histUpn = sam;
                            string histMail = "";
                            string histDept = "";
                            string histTitle = "";
                            int histBadPwd = 0;
                            DateTime? histPwdSet = null;
                            DateTime? histLastBad = null;
                            DateTime? histLastLogon = null;
                            DateTime? histExpires = null;
                            bool histMustChange = false;
                            bool histPwdNeverExp = false;
                            List<string> histGroups = new List<string>();
                            string histPSO = null;

                            if (disabledAccountCache.ContainsKey(sam))
                            {
                                isDisabled = disabledAccountCache[sam];
                            }
                            else
                            {
                                try
                                {
                                    using (DirectorySearcher searcher = new DirectorySearcher())
                                    {
                                        searcher.Filter = string.Format("(&(objectCategory=person)(objectClass=user)(samaccountname={0}))", sam);
                                        searcher.PropertiesToLoad.AddRange(new string[] {
                                            "displayname", "useraccountcontrol", "mail", "department", "title",
                                            "userprincipalname", "pwdlastset", "badpwdcount", "lastbadpasswordattempt",
                                            "lastlogontimestamp", "accountexpires", "memberof", "msds-resultantpso"
                                        });
                                        SearchResult sr = searcher.FindOne();
                                        if (sr != null)
                                        {
                                            int uac = sr.Properties["useraccountcontrol"].Count > 0 ? Convert.ToInt32(sr.Properties["useraccountcontrol"][0]) : 0;
                                            isDisabled = (uac & 2) != 0;
                                            histPwdNeverExp = (uac & 0x10000) != 0;

                                            if (sr.Properties.Contains("displayname") && sr.Properties["displayname"].Count > 0)
                                                histDisp = (string)sr.Properties["displayname"][0];
                                            if (sr.Properties.Contains("userprincipalname") && sr.Properties["userprincipalname"].Count > 0)
                                                histUpn = (string)sr.Properties["userprincipalname"][0];
                                            if (sr.Properties.Contains("mail") && sr.Properties["mail"].Count > 0)
                                                histMail = (string)sr.Properties["mail"][0];
                                            if (sr.Properties.Contains("department") && sr.Properties["department"].Count > 0)
                                                histDept = (string)sr.Properties["department"][0];
                                            if (sr.Properties.Contains("title") && sr.Properties["title"].Count > 0)
                                                histTitle = (string)sr.Properties["title"][0];
                                            if (sr.Properties.Contains("badpwdcount") && sr.Properties["badpwdcount"].Count > 0)
                                                histBadPwd = Convert.ToInt32(sr.Properties["badpwdcount"][0]);

                                            if (sr.Properties.Contains("pwdlastset") && sr.Properties["pwdlastset"].Count > 0)
                                            {
                                                long ft = GetInt64FromLargeInt(sr.Properties["pwdlastset"][0]);
                                                if (ft == 0) histMustChange = true;
                                                else { try { histPwdSet = DateTime.FromFileTime(ft); } catch { } }
                                            }
                                            if (sr.Properties.Contains("lastbadpasswordattempt") && sr.Properties["lastbadpasswordattempt"].Count > 0)
                                            {
                                                long ft = GetInt64FromLargeInt(sr.Properties["lastbadpasswordattempt"][0]);
                                                if (ft > 0) { try { histLastBad = DateTime.FromFileTime(ft); } catch { } }
                                            }
                                            if (sr.Properties.Contains("lastlogontimestamp") && sr.Properties["lastlogontimestamp"].Count > 0)
                                            {
                                                long ft = GetInt64FromLargeInt(sr.Properties["lastlogontimestamp"][0]);
                                                if (ft > 0) { try { histLastLogon = DateTime.FromFileTime(ft); } catch { } }
                                            }
                                            if (sr.Properties.Contains("accountexpires") && sr.Properties["accountexpires"].Count > 0)
                                            {
                                                long ft = GetInt64FromLargeInt(sr.Properties["accountexpires"][0]);
                                                if (ft > 0 && ft != 9223372036854775807L && ft != 0x7FFFFFFFFFFFFFFFL) { try { histExpires = DateTime.FromFileTime(ft); } catch { } }
                                            }
                                            if (sr.Properties.Contains("memberof"))
                                            {
                                                foreach (object grp in sr.Properties["memberof"])
                                                {
                                                    string grpStr = grp != null ? grp.ToString() : "";
                                                    if (grpStr.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        int commaIdx = grpStr.IndexOf(',');
                                                        string grpName = commaIdx > 3 ? grpStr.Substring(3, commaIdx - 3) : grpStr.Substring(3);
                                                        histGroups.Add(grpName);
                                                    }
                                                }
                                            }
                                            if (sr.Properties.Contains("msds-resultantpso") && sr.Properties["msds-resultantpso"].Count > 0)
                                            {
                                                string psoStr = sr.Properties["msds-resultantpso"][0].ToString();
                                                if (psoStr.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                                                {
                                                    int commaIdx = psoStr.IndexOf(',');
                                                    histPSO = commaIdx > 3 ? psoStr.Substring(3, commaIdx - 3) : psoStr.Substring(3);
                                                }
                                                else
                                                {
                                                    histPSO = psoStr;
                                                }
                                            }
                                        }
                                    }
                                }
                                catch { }
                                disabledAccountCache[sam] = isDisabled;
                            }

                            if (isDisabled) continue; // SKIP DISABLED USERS FROM HISTORICAL LIST!

                            LockoutEventItem histLock = kvp.Value.Find(e => !string.IsNullOrEmpty(e.CallerComputer));
                            string histCaller = histLock != null ? histLock.CallerComputer : (kvp.Value.Count > 0 ? (kvp.Value[0].CallerComputer ?? "") : "");
                            string histDC = histLock != null ? histLock.DomainController : (kvp.Value.Count > 0 ? kvp.Value[0].DomainController : "");

                            historicalUsers.Add(new UserRecord
                            {
                                SamAccountName = sam,
                                DisplayName = histDisp,
                                UserPrincipalName = histUpn,
                                EmailAddress = histMail,
                                Department = histDept,
                                Title = histTitle,
                                Enabled = true,
                                IsCurrentlyLocked = false,
                                BadPasswordCount = histBadPwd,
                                PasswordLastSet = histPwdSet,
                                LastBadPasswordAttempt = histLastBad,
                                LastLogonTimestamp = histLastLogon,
                                AccountExpires = histExpires,
                                MustChangePasswordAtNextLogon = histMustChange,
                                PasswordNeverExpires = histPwdNeverExp,
                                MemberOfGroups = histGroups,
                                ResultantPSO = histPSO,
                                Events = kvp.Value,
                                EventCount = kvp.Value.Count,
                                LatestEventTime = kvp.Value.Count > 0 ? (DateTime?)kvp.Value[0].TimeCreated : null,
                                LatestCaller = histCaller,
                                LatestDC = histDC
                            });
                        }

                        // Enforce: ONLY include historical users that have > 0 recent lockout events!
                        historicalUsers.RemoveAll(u => u.Events == null || u.Events.Count == 0);
                        historicalUsers.Sort((a, b) => Nullable.Compare(b.LatestEventTime, a.LatestEventTime));
                    }
                }
                catch (Exception ex)
                {
                    errorMsg = ex.Message;
                }

                // Update UI on main thread
                this.BeginInvoke((Action)(() =>
                {
                    _btnRefreshLockouts.Enabled = true;
                    _progressBar.Visible = false;
                    _discoveredDCs = dcs;

                    _domainInfoLabel.Text = string.Format("Domain: {0} ({1} DCs online)", domainName, dcs.Count);

                    if (errorMsg != null && dcs.Count == 0)
                    {
                        _statusLabel.Text = "Notice: " + errorMsg + " (No domain controllers could be contacted)";
                        MessageBox.Show(
                            "Could not contact a Domain Controller from this computer.\r\n\r\n" +
                            "Make sure this machine is domain-joined and connected to your corporate network or VPN.\r\n\r\n" +
                            "Verify that your account has domain administrative or security event log read permissions.",
                            "Domain Connection Notice",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        return;
                    }

                    _currentLockedUsers = lockedUsers;
                    _historicalUsers = historicalUsers;
                    PopulateAccountLists();

                    _statusLabel.Text = string.Format("Scan complete. Currently locked: {0} active users | Historically locked: {1} active users.", lockedUsers.Count, historicalUsers.Count);
                    _countsLabel.Text = string.Format("Locked: {0}  |  Historical: {1}", lockedUsers.Count, historicalUsers.Count);
                }));
            });
        }

        private void PopulateAccountLists()
        {
            _lstCurrentAccounts.Items.Clear();
            foreach (var u in _currentLockedUsers)
            {
                _lstCurrentAccounts.Items.Add(u);
            }

            _lstHistoricalAccounts.Items.Clear();
            foreach (var u in _historicalUsers)
            {
                _lstHistoricalAccounts.Items.Add(u);
            }

            if (_lstCurrentAccounts.Items.Count > 0)
            {
                _lstCurrentAccounts.SelectedIndex = 0;
            }
        }

        // -------------------------------------------------------------
        // USER SELECTION & POPULATE CALLER COMPUTERS
        // -------------------------------------------------------------
        private void AccountSelectionChanged(object sender, EventArgs e)
        {
            ListBox lst = sender as ListBox;
            if (lst == null || lst.SelectedItem == null) return;

            // Deselect the other list box so only one account is highlighted at a time
            if (lst == _lstCurrentAccounts && _lstHistoricalAccounts.SelectedItem != null)
            {
                _lstHistoricalAccounts.ClearSelected();
            }
            else if (lst == _lstHistoricalAccounts && _lstCurrentAccounts.SelectedItem != null)
            {
                _lstCurrentAccounts.ClearSelected();
            }

            _selectedUser = lst.SelectedItem as UserRecord;
            if (_selectedUser == null) return;

            _btnUnlock.Enabled = _selectedUser.IsCurrentlyLocked;
            _btnResetPassword.Enabled = true;

            // Clear old session & computer details
            _selectedComputer = null;
            _selectedSession = null;
            _lvSessions.Items.Clear();
            _btnLogoffUser.Enabled = false;
            _btnRebootComputer.Enabled = false;

            // 1. Initial render with existing/cached data
            PopulateCallerComputersAndRender(_selectedUser);

            // 2. Asynchronously fetch deep targeted forensics (4625, 4771, 4624) specifically for this user
            UserRecord targetForForensics = _selectedUser;
            ThreadPool.QueueUserWorkItem(state =>
            {
                FetchTargetedForensicEvents(targetForForensics);
            });
        }

        private void PopulateCallerComputersAndRender(UserRecord user)
        {
            if (user == null) return;

            // Populate Caller Computers & Client IPs (Column 2)
            _lstCallerComputers.BeginUpdate();
            _lstCallerComputers.Items.Clear();

            Dictionary<string, CallerComputerItem> callerMap = new Dictionary<string, CallerComputerItem>(StringComparer.OrdinalIgnoreCase);

            if (!string.IsNullOrEmpty(user.LatestCaller))
            {
                callerMap[user.LatestCaller] = new CallerComputerItem
                {
                    ComputerName = user.LatestCaller,
                    EventCount = 1,
                    LatestEvent = user.LatestEventTime
                };
            }

            foreach (var evt in user.Events)
            {
                string target = !string.IsNullOrEmpty(evt.CallerComputer) ? evt.CallerComputer : null;
                if (!string.IsNullOrEmpty(target))
                {
                    if (!callerMap.ContainsKey(target))
                    {
                        callerMap[target] = new CallerComputerItem
                        {
                            ComputerName = target,
                            EventCount = 0,
                            LatestEvent = evt.TimeCreated
                        };
                    }
                    callerMap[target].EventCount++;
                    if (callerMap[target].LatestEvent == null || evt.TimeCreated > callerMap[target].LatestEvent)
                    {
                        callerMap[target].LatestEvent = evt.TimeCreated;
                    }
                }

                if (!string.IsNullOrEmpty(evt.SourceIp) && !string.Equals(evt.SourceIp, target, StringComparison.OrdinalIgnoreCase))
                {
                    string ipTarget = evt.SourceIp;
                    if (!callerMap.ContainsKey(ipTarget))
                    {
                        callerMap[ipTarget] = new CallerComputerItem
                        {
                            ComputerName = ipTarget,
                            EventCount = 0,
                            LatestEvent = evt.TimeCreated
                        };
                    }
                    callerMap[ipTarget].EventCount++;
                    if (callerMap[ipTarget].LatestEvent == null || evt.TimeCreated > callerMap[ipTarget].LatestEvent)
                    {
                        callerMap[ipTarget].LatestEvent = evt.TimeCreated;
                    }
                }
            }

            foreach (var item in callerMap.Values)
            {
                _lstCallerComputers.Items.Add(item);
            }
            _lstCallerComputers.EndUpdate();

            if (_lstCallerComputers.Items.Count > 0)
            {
                _lstCallerComputers.SelectedIndex = 0;
            }
            else
            {
                _rtbComputerDetails.Text = "No caller computers or client IP addresses recorded for this account.\r\n(Some authentications like NTLM or direct LDAP queries may omit workstation names).";
            }

            // Render Account Details & Root Cause Forensics (Column 1)
            RenderAccountDetails(user, callerMap.Keys);
        }

        private void FetchTargetedForensicEvents(UserRecord user)
        {
            if (user == null) return;
            string sam = user.SamAccountName;
            List<string> dcs = _discoveredDCs;
            if (dcs == null || dcs.Count == 0) return;

            List<LockoutEventItem> deepEvents = new List<LockoutEventItem>();

            foreach (string dc in dcs)
            {
                try
                {
                    // Targeted query strictly for this single user: Logon Failure (4625), Kerberos Pre-Auth Failure (4771), Logon Success (4624)
                    // Bounded to recent 7 days (604800000 ms) and limited to 50 records per DC
                    string xpath = string.Format(
                        "*[System[((EventID=4625 or EventID=4771 or EventID=4624)) and TimeCreated[timediff(@SystemTime) <= 604800000]]] and (*[EventData[Data[@Name='TargetUserName']='{0}']] or *[EventData[Data[@Name='TargetUserName']='{0}@{1}']])",
                        sam, _domainName ?? "");

                    EventLogQuery query = new EventLogQuery("Security", PathType.LogName, xpath);
                    query.Session = new EventLogSession(dc);

                    using (EventLogReader reader = new EventLogReader(query))
                    {
                        EventRecord record;
                        int count = 0;
                        while ((record = reader.ReadEvent()) != null && count < 50)
                        {
                            count++;
                            int id = record.Id;
                            string caller = null;
                            string sourceIp = null;
                            string logonType = null;
                            string subStatus = null;

                            if (id == 4625)
                            {
                                sourceIp = GetNamedEventData(record, "IpAddress");
                                caller = GetNamedEventData(record, "WorkstationName");
                                logonType = GetNamedEventData(record, "LogonType");
                                subStatus = GetNamedEventData(record, "SubStatus");
                                if (string.IsNullOrEmpty(subStatus)) subStatus = GetNamedEventData(record, "Status");
                            }
                            else if (id == 4771)
                            {
                                sourceIp = GetNamedEventData(record, "ClientAddress");
                                if (string.IsNullOrEmpty(sourceIp)) sourceIp = GetNamedEventData(record, "IpAddress");
                                subStatus = GetNamedEventData(record, "FailureCode");
                                if (string.IsNullOrEmpty(subStatus)) subStatus = GetNamedEventData(record, "Status");
                            }
                            else if (id == 4624)
                            {
                                caller = GetNamedEventData(record, "WorkstationName");
                                sourceIp = GetNamedEventData(record, "IpAddress");
                                logonType = GetNamedEventData(record, "LogonType");
                            }

                            if (!string.IsNullOrEmpty(sourceIp))
                            {
                                sourceIp = sourceIp.Replace("::ffff:", "").Trim();
                                if (sourceIp == "-" || sourceIp == "127.0.0.1" || sourceIp == "::1") sourceIp = null;
                            }
                            if (!string.IsNullOrEmpty(caller))
                            {
                                caller = caller.Trim();
                                if (caller == "-" || caller == "?") caller = null;
                            }

                            deepEvents.Add(new LockoutEventItem
                            {
                                TimeCreated = record.TimeCreated ?? DateTime.Now,
                                EventId = id,
                                CallerComputer = !string.IsNullOrEmpty(caller) ? NormalizeComputer(caller) : null,
                                SourceIp = sourceIp,
                                LogonType = DecodeLogonType(logonType),
                                StatusOrCode = DecodeSubStatus(subStatus),
                                DomainController = dc,
                                RecordId = record.RecordId ?? 0
                            });
                        }
                    }
                }
                catch { }
            }

            if (deepEvents.Count > 0)
            {
                this.BeginInvoke((Action)(() =>
                {
                    if (_selectedUser != null && string.Equals(_selectedUser.SamAccountName, sam, StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var de in deepEvents)
                        {
                            if (!_selectedUser.Events.Exists(e => e.EventId == de.EventId && e.RecordId == de.RecordId && e.DomainController == de.DomainController))
                            {
                                _selectedUser.Events.Add(de);
                            }
                        }
                        _selectedUser.Events.Sort((a, b) => b.TimeCreated.CompareTo(a.TimeCreated));
                        PopulateCallerComputersAndRender(_selectedUser);
                    }
                }));
            }
        }

        private void RenderAccountDetails(UserRecord u, IEnumerable<string> callers)
        {
            string callerStr = string.Join(", ", callers);
            bool isWifi = Regex.IsMatch(callerStr, "(?i)radius|nps|wifi|wireless") ||
                          u.Events.Exists(ev => Regex.IsMatch(ev.CallerComputer ?? "", "(?i)radius|nps|wifi"));
            bool isRdp = Regex.IsMatch(callerStr, "(?i)rdp|term|ts|gateway");
            bool isWorkstation = !string.IsNullOrEmpty(callerStr) && !isWifi && !isRdp;

            bool isRecentPasswordChange = u.PasswordLastSet.HasValue && (DateTime.Now - u.PasswordLastSet.Value).TotalHours <= 72;

            string rootCause;
            string remediation;

            bool isSharedOrKiosk = Regex.IsMatch(u.SamAccountName, "(?i)temp|guest|share|kiosk|contract|frontdesk") ||
                                   Regex.IsMatch(callerStr, "(?i)shared|kiosk|frontdesk|conf|multi|guest|terminal|pool");

            if (u.MustChangePasswordAtNextLogon)
            {
                rootCause = "[MUST CHANGE PASSWORD] User Must Change Password at Next Logon Active";
                remediation = "* WHAT OCCURRED:\r\n  The account is flagged in Active Directory with 'User must change password at next logon'. Non-interactive authentications (corporate 802.1X Wi-Fi, background mobile sync, mapped network drives, scheduled tasks) cannot prompt for password changes and fail immediately, rapidly exceeding the lockout threshold.\r\n\r\n* REMEDIATION ACTION PLAN:\r\n  1. Click 'RESET USER PASSWORD' in this tool to set a known password, or have the user log in interactively on a domain workstation.\r\n  2. Click 'UNLOCK SELECTED USER'.";
            }
            else if (isWifi)
            {
                rootCause = "[WIRELESS / RADIUS] Enterprise 802.1X Wireless Credential Loop (NPS / RADIUS Proxy)";
                remediation = string.Format(
                    "* WHAT OCCURRED (AUTHENTICATION PROXY):\r\n" +
                    "  The user recently updated their Active Directory password, but an endpoint (smartphone, tablet, personal laptop, or IoT device) is still attempting to connect to corporate 802.1X Wi-Fi using the PREVIOUS password.\r\n" +
                    "  Because Network Policy Server (NPS) acts as the RADIUS proxy between Wi-Fi Access Points and Active Directory, Domain Controllers record the NPS server ('{0}') as the caller in Event 4740/4771, masking the physical user device.\r\n\r\n" +
                    "* STEP-BY-STEP NPS / RADIUS TROUBLESHOOTING PLAYBOOK:\r\n" +
                    "  1. Log into your NPS server ('{0}') and open Event Viewer -> Windows Logs -> Security.\r\n" +
                    "  2. Filter for Event ID 6273 ('Network Policy Server discarded or denied an authentication request') matching user '{1}'.\r\n" +
                    "  3. Inspect 'Calling-Station-Id': This field contains the client's physical MAC address (e.g., 3C-22-FB-A1-09-E4).\r\n" +
                    "  4. Inspect 'Client-Friendly-Name' / 'NAS-Identifier': This specifies the exact Wireless Access Point or switch where the device is located.\r\n" +
                    "  5. Cross-reference the MAC address in your DHCP server leases or MDM (Intune/Jamf) to identify the physical device (e.g. employee iPhone, Android, or laptop).\r\n\r\n" +
                    "* REMEDIATION ACTION PLAN:\r\n" +
                    "  1. On the offending device: Open Wi-Fi settings -> Select organization Wi-Fi -> Tap 'Forget This Network' (or toggle Wi-Fi off).\r\n" +
                    "  2. In this tool: Click 'UNLOCK SELECTED USER'. The account will now remain unlocked.\r\n" +
                    "  3. On the device: Re-select the Wi-Fi network and enter the new domain password when prompted.",
                    callerStr, u.SamAccountName);
            }
            else if (isSharedOrKiosk)
            {
                rootCause = "[SHARED HOST SESSION] Stale Active or Disconnected Session on Multi-User Workstation";
                remediation = string.Format(
                    "* WHAT OCCURRED:\r\n  A user session was left active or disconnected on shared / multi-user computer '{0}'. When passwords are updated, expired, or rotated, background tasks and system processes in that lingering session continue attempting Kerberos ticket renewal or network share synchronization with expired credentials. This triggers repeated lockouts immediately after the account is unlocked.\r\n\r\n* REMEDIATION ACTION PLAN:\r\n  1. Select '{0}' in the middle column under Caller Computers.\r\n  2. Review the active and disconnected sessions displayed on the right panel via QUSER.\r\n  3. Select the stale user session and click 'LOG OFF USER SESSION', or click 'REBOOT CALLER COMPUTER' to cleanly restart the workstation.\r\n  4. Click 'UNLOCK SELECTED USER' once the session is terminated.",
                    callerStr);
            }
            else if (isRecentPasswordChange && isWorkstation)
            {
                rootCause = "[CONFIRMED STALE CREDENTIALS] Password Changed Recently While Devices Held Old Credentials";
                remediation = string.Format(
                    "* WHAT OCCURRED:\r\n  The user changed their Active Directory password {0:F1} hours ago ({1:yyyy-MM-dd HH:mm:ss}). Caller device '{2}' recorded failed authentication attempts shortly after this change.\r\n  This confirms that stored credentials in Windows Credential Manager, a mapped network drive, an email client, or a background scheduled task are submitting outdated credentials.\r\n\r\n* REMEDIATION ACTION PLAN:\r\n  1. Log into or remote into '{2}'.\r\n  2. Open Start Menu -> Control Panel -> Credential Manager -> Windows Credentials.\r\n  3. Remove any saved credentials pointing to domain resources or intranet sites.\r\n  4. Run 'klist purge' in Command Prompt on the workstation to flush stale Kerberos tickets.\r\n  5. Click 'UNLOCK SELECTED USER' in this tool.",
                    (DateTime.Now - u.PasswordLastSet.Value).TotalHours,
                    u.PasswordLastSet.Value,
                    callerStr);
            }
            else if (isWorkstation)
            {
                rootCause = "[CREDENTIAL MANAGER] Expired Saved Credentials in Windows Credential Manager / Mapped Drive";
                remediation = string.Format(
                    "* WHAT OCCURRED:\r\n  Caller workstation '{0}' is holding outdated credentials saved in Windows Credential Manager or local application vaults (e.g., mapped network drives, shared printers, Outlook, Teams, or intranet web servers). In the background, network authentication attempts fail with STATUS_WRONG_PASSWORD (0xC000006A).\r\n\r\n* REMEDIATION ACTION PLAN:\r\n  1. Log into or remote into '{0}'.\r\n  2. Open Start Menu -> Control Panel -> Credential Manager -> Windows Credentials.\r\n  3. Under 'Windows Credentials' and 'Generic Credentials', locate and remove any stored entries pointing to domain resources.\r\n  4. If persistent, open an elevated command prompt on the workstation and run 'klist purge' to flush Kerberos ticket caches.\r\n  5. Click 'UNLOCK SELECTED USER' in this tool.",
                    callerStr);
            }
            else if (isRdp)
            {
                rootCause = "[REMOTE DESKTOP] Remote Desktop / Terminal Server Authentication";
                remediation = string.Format(
                    "* WHAT OCCURRED:\r\n  Lockout events originated from a Remote Desktop Host or Terminal Server ('{0}'). Stale disconnected sessions or saved credentials in an .rdp connection profile are submitting invalid credentials.\r\n\r\n* REMEDIATION ACTION PLAN:\r\n  1. Select '{0}' in the middle column.\r\n  2. Review active and disconnected sessions via QUSER on the right.\r\n  3. Log off any disconnected sessions for this user, then click 'UNLOCK SELECTED USER'.",
                    callerStr);
            }
            else
            {
                rootCause = "[BAD PASSWORD] Multiple Incorrect Password Attempts Exceeded Threshold";
                remediation = "* WHAT OCCURRED:\r\n  The user or an application exceeded the domain password lockout threshold. Review the Event audit timeline below for the reporting domain controller, caller workstation, client IP, and exact timestamps.\r\n\r\n* REMEDIATION ACTION PLAN:\r\n  1. Verify Caps Lock is turned off on the user's keyboard.\r\n  2. Click 'UNLOCK SELECTED USER'.\r\n  3. If the user does not remember their password, click 'RESET USER PASSWORD' to set a new temporary password.";
            }

            System.Text.StringBuilder sb = new System.Text.StringBuilder();

            // 1. Account Security Profile & Timestamps
            sb.AppendLine("ACCOUNT SECURITY PROFILE & TIMESTAMPS");
            sb.AppendLine("=====================================");
            sb.AppendLine(string.Format("Username:                 {0}", u.SamAccountName));
            sb.AppendLine(string.Format("Display Name:             {0}", u.DisplayName));
            sb.AppendLine(string.Format("UPN:                      {0}", string.IsNullOrEmpty(u.UserPrincipalName) ? u.SamAccountName : u.UserPrincipalName));
            sb.AppendLine(string.Format("Email:                    {0}", string.IsNullOrEmpty(u.EmailAddress) ? "(not set)" : u.EmailAddress));
            sb.AppendLine(string.Format("Department:               {0}", string.IsNullOrEmpty(u.Department) ? "(not set)" : u.Department));
            sb.AppendLine(string.Format("Title:                    {0}", string.IsNullOrEmpty(u.Title) ? "(not set)" : u.Title));
            sb.AppendLine(string.Format("Active / Enabled:         Yes (Disabled accounts excluded)"));
            sb.AppendLine(string.Format("CURRENTLY LOCKED:         {0}", u.IsCurrentlyLocked ? "YES (CURRENTLY LOCKED)" : "NO (HISTORICAL RECORD)"));
            sb.AppendLine(string.Format("Bad Password Count:       {0}", u.BadPasswordCount));
            sb.AppendLine(string.Format("Last Bad Password Time:   {0}", u.LastBadPasswordAttempt.HasValue ? u.LastBadPasswordAttempt.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(not recorded)"));
            sb.AppendLine(string.Format("Last Successful Logon:    {0}", u.LastLogonTimestamp.HasValue ? u.LastLogonTimestamp.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(not recorded)"));

            string pwdAgeStr;
            if (u.MustChangePasswordAtNextLogon)
            {
                pwdAgeStr = "MUST CHANGE PASSWORD AT NEXT LOGON (Immediate service/Wi-Fi lockout hazard!)";
            }
            else if (u.PasswordLastSet.HasValue)
            {
                TimeSpan age = DateTime.Now - u.PasswordLastSet.Value;
                if (age.TotalHours < 24)
                    pwdAgeStr = string.Format("{0:yyyy-MM-dd HH:mm:ss} ({1:F1} hours ago - RECENT CHANGE)", u.PasswordLastSet.Value, age.TotalHours);
                else
                    pwdAgeStr = string.Format("{0:yyyy-MM-dd HH:mm:ss} ({1} days ago)", u.PasswordLastSet.Value, (int)age.TotalDays);
            }
            else
            {
                pwdAgeStr = "(not recorded)";
            }
            sb.AppendLine(string.Format("Password Last Changed:    {0}", pwdAgeStr));

            string pwdExpStr = u.PasswordNeverExpires
                ? "Never (Password Never Expires enabled)"
                : (u.AccountExpires.HasValue ? string.Format("Account expires: {0:yyyy-MM-dd}", u.AccountExpires.Value) : "Subject to Active Directory Domain Policy");
            sb.AppendLine(string.Format("Password Expiry Status:   {0}", pwdExpStr));
            sb.AppendLine(string.Format("Account Expiration:       {0}", u.AccountExpires.HasValue ? u.AccountExpires.Value.ToString("yyyy-MM-dd HH:mm:ss") : "Never"));
            sb.AppendLine(string.Format("Primary Security Groups:  {0}", (u.MemberOfGroups != null && u.MemberOfGroups.Count > 0) ? string.Join(", ", u.MemberOfGroups.ToArray()) : "(none or Domain Users)"));

            string policyDesc = !string.IsNullOrEmpty(u.ResultantPSO)
                ? string.Format("Fine-Grained Password Policy (PSO: '{0}')", u.ResultantPSO)
                : "Default Domain Password Policy";
            sb.AppendLine(string.Format("Password Policy:          {0}", policyDesc));

            // Check for previous unlock events (Event 4767) vs Automatic Policy Timer Expiration (FGPP / Domain)
            LockoutEventItem latestUnlock = u.Events.Find(ev => ev.EventId == 4767);
            LockoutEventItem latestLockout = u.Events.Find(ev => ev.EventId == 4740);

            if (latestUnlock != null)
            {
                sb.AppendLine(string.Format("Last Unlocked By:         {0} ({1:yyyy-MM-dd HH:mm:ss} on DC {2})",
                    string.IsNullOrEmpty(latestUnlock.UnlockedBy) ? "(Administrator not recorded)" : latestUnlock.UnlockedBy,
                    latestUnlock.TimeCreated,
                    latestUnlock.DomainController));
                sb.AppendLine("Unlock Resolution:        Manual Administrator Action (Security Event 4767)");
            }
            else if (!u.IsCurrentlyLocked && latestLockout != null)
            {
                sb.AppendLine("Last Unlocked By:         (No 4767 unlock events in cached Security log)");
                sb.AppendLine(string.Format("Unlock Resolution:        AUTOMATIC UNLOCK via {0} (Lockout duration timer expired)",
                    !string.IsNullOrEmpty(u.ResultantPSO) ? ("FGPP '" + u.ResultantPSO + "'") : "Domain Policy"));
            }
            else
            {
                sb.AppendLine("Last Unlocked By:         (No 4767 unlock events in cached Security log)");
            }

            // Post-Unlock Logon Status (correlating last successful logon with latest lockout event)
            if (latestLockout != null && u.LastLogonTimestamp.HasValue)
            {
                if (u.LastLogonTimestamp.Value > latestLockout.TimeCreated)
                {
                    sb.AppendLine(string.Format("Post-Unlock Logon (AD):   YES - User logged on at {0:yyyy-MM-dd HH:mm:ss} (Active Directory confirmed)", u.LastLogonTimestamp.Value));
                }
                else
                {
                    sb.AppendLine(string.Format("Post-Unlock Logon (AD):   NO - No successful domain logons recorded since latest lockout ({0:yyyy-MM-dd HH:mm:ss})", latestLockout.TimeCreated));
                }
            }

            int lockoutCount = 0;
            int unlockCount = 0;
            int failureCount = 0;
            int successCount = 0;
            foreach (var ev in u.Events)
            {
                if (ev.EventId == 4767) unlockCount++;
                else if (ev.EventId == 4740) lockoutCount++;
                else if (ev.EventId == 4625 || ev.EventId == 4771) failureCount++;
                else if (ev.EventId == 4624) successCount++;
            }
            sb.AppendLine(string.Format("Lockout Events (4740):    {0}", lockoutCount));
            sb.AppendLine(string.Format("Unlock Events (4767):     {0}", unlockCount));
            if (failureCount > 0)
                sb.AppendLine(string.Format("Logon Failures (4625/4771):{0}", failureCount));
            if (successCount > 0)
                sb.AppendLine(string.Format("Successful Logons (4624): {0}", successCount));
            sb.AppendLine();

            // 2. Root Cause Diagnosis & Action Plan
            sb.AppendLine("ROOT CAUSE DIAGNOSIS");
            sb.AppendLine("====================");
            sb.AppendLine("Likely Cause: " + rootCause);
            sb.AppendLine();
            sb.AppendLine("Remediation Action Plan:");
            sb.AppendLine(remediation);
            sb.AppendLine();

            // 3. Caller Computers & Source Devices
            sb.AppendLine("CALLER COMPUTERS & SOURCE DEVICES");
            sb.AppendLine("=================================");
            if (callers != null)
            {
                int cCount = 0;
                foreach (string c in callers)
                {
                    cCount++;
                    bool isIp = Regex.IsMatch(c, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$");
                    if (isIp)
                        sb.AppendLine(string.Format("* {0}  [Client Source IP - captured from Event 4625 / 4771]", c));
                    else
                        sb.AppendLine(string.Format("* {0}  [Calling Hostname - reported in Event 4740 / 4625]", c));
                }
                if (cCount == 0) sb.AppendLine("(None recorded in Security logs)");
            }
            else
            {
                sb.AppendLine("(None recorded in Security logs)");
            }
            sb.AppendLine();

            // 4. Event Audit Log Timeline (Lockout 4740, Unlock 4767, Logon Failure 4625, Kerberos 4771, Logon Success 4624)
            sb.AppendLine("EVENT AUDIT LOG TIMELINE");
            sb.AppendLine("========================");
            if (u.Events.Count == 0)
            {
                sb.AppendLine("No recent 4740 lockout, 4767 unlock, or 4625 failure events cached from online DCs.");
            }
            else
            {
                foreach (var evt in u.Events)
                {
                    if (evt.EventId == 4767)
                    {
                        sb.AppendLine(string.Format("{0:yyyy-MM-dd HH:mm:ss} | Event 4767 (ACCOUNT UNLOCKED) | Unlocked By: {1} | DC: {2} | Record: {3}",
                            evt.TimeCreated,
                            string.IsNullOrEmpty(evt.UnlockedBy) ? "(Administrator not recorded)" : evt.UnlockedBy,
                            evt.DomainController,
                            evt.RecordId));
                    }
                    else if (evt.EventId == 4740)
                    {
                        sb.AppendLine(string.Format("{0:yyyy-MM-dd HH:mm:ss} | Event 4740 (ACCOUNT LOCKED)   | Caller: {1} | DC: {2} | Record: {3}",
                            evt.TimeCreated,
                            string.IsNullOrEmpty(evt.CallerComputer) ? "(Caller computer not recorded)" : evt.CallerComputer,
                            evt.DomainController,
                            evt.RecordId));
                    }
                    else if (evt.EventId == 4625)
                    {
                        string ipInfo = !string.IsNullOrEmpty(evt.SourceIp) ? evt.SourceIp : "(IP not recorded)";
                        string wsInfo = !string.IsNullOrEmpty(evt.CallerComputer) ? evt.CallerComputer : "(Workstation not recorded)";
                        sb.AppendLine(string.Format("{0:yyyy-MM-dd HH:mm:ss} | Event 4625 (LOGON FAILURE)    | Source IP: {1} | Workstation: {2} | {3} | SubStatus: {4} | DC: {5}",
                            evt.TimeCreated,
                            ipInfo,
                            wsInfo,
                            !string.IsNullOrEmpty(evt.LogonType) ? evt.LogonType : "Network (3)",
                            !string.IsNullOrEmpty(evt.StatusOrCode) ? evt.StatusOrCode : "0xC000006A (Bad Password)",
                            evt.DomainController));
                    }
                    else if (evt.EventId == 4771)
                    {
                        string ipInfo = !string.IsNullOrEmpty(evt.SourceIp) ? evt.SourceIp : "(IP not recorded)";
                        sb.AppendLine(string.Format("{0:yyyy-MM-dd HH:mm:ss} | Event 4771 (KERBEROS PREAUTH)  | Client IP: {1} | Code: {2} | DC: {3}",
                            evt.TimeCreated,
                            ipInfo,
                            !string.IsNullOrEmpty(evt.StatusOrCode) ? evt.StatusOrCode : "0x18 (Pre-Auth Failed)",
                            evt.DomainController));
                    }
                    else if (evt.EventId == 4624)
                    {
                        string ipInfo = !string.IsNullOrEmpty(evt.SourceIp) ? evt.SourceIp : "(IP not recorded)";
                        string wsInfo = !string.IsNullOrEmpty(evt.CallerComputer) ? evt.CallerComputer : "(Workstation not recorded)";
                        sb.AppendLine(string.Format("{0:yyyy-MM-dd HH:mm:ss} | Event 4624 (SUCCESSFUL LOGON) | Workstation: {1} | IP: {2} | {3} | DC: {4}",
                            evt.TimeCreated,
                            wsInfo,
                            ipInfo,
                            !string.IsNullOrEmpty(evt.LogonType) ? evt.LogonType : "Interactive",
                            evt.DomainController));
                    }
                }
            }

            _rtbAccountDetails.Text = sb.ToString();
            _statusLabel.Text = string.Format("Selected {0}. Choose a caller computer in the middle column to inspect network status and sessions.", u.SamAccountName);
        }

        // -------------------------------------------------------------
        // CALLER COMPUTER SELECTION & QUERY COMPUTER AD + QUSER
        // -------------------------------------------------------------
        private void CallerSelectionChanged(object sender, EventArgs e)
        {
            if (_lstCallerComputers.SelectedItem == null)
            {
                _selectedComputer = null;
                _btnRebootComputer.Enabled = false;
                _lvSessions.Items.Clear();
                _btnLogoffUser.Enabled = false;
                return;
            }

            CallerComputerItem compItem = _lstCallerComputers.SelectedItem as CallerComputerItem;
            if (compItem == null) return;

            _selectedComputer = compItem.ComputerName;
            _btnRebootComputer.Enabled = !_selectedComputer.StartsWith("IP: ", StringComparison.OrdinalIgnoreCase);

            // Render Computer AD Details & Network Ping
            RenderComputerAdDetails(_selectedComputer);

            // Automatically Query QUSER Sessions (with 10-second timeout)
            QueryQUserAsync(_selectedComputer);
        }

        private void RenderComputerAdDetails(string computerName)
        {
            _rtbComputerDetails.Text = string.Format("Querying network status and Active Directory record for '{0}'...", computerName);

            ThreadPool.QueueUserWorkItem(state =>
            {
                string infoText;
                try
                {
                    string targetHost = computerName;
                    if (targetHost.StartsWith("IP: ", StringComparison.OrdinalIgnoreCase))
                        targetHost = targetHost.Substring(4).Trim();

                    string shortName = targetHost.Contains(".") ? targetHost.Split('.')[0] : targetHost;
                    string resolvedIp = "(Resolving...)";
                    string pingStatus = "Unknown";

                    // 1. Resolve DNS IPv4
                    try
                    {
                        IPHostEntry host = Dns.GetHostEntry(targetHost);
                        List<string> ips = new List<string>();
                        foreach (IPAddress ip in host.AddressList)
                        {
                            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                                ips.Add(ip.ToString());
                        }
                        resolvedIp = ips.Count > 0 ? string.Join(", ", ips.ToArray()) : "(No IPv4 registered)";
                    }
                    catch
                    {
                        resolvedIp = targetHost.Contains(".") && Regex.IsMatch(targetHost, @"^\d+\.\d+\.\d+\.\d+$") ? targetHost : "Unresolved (Not in DNS)";
                    }

                    // 2. Fast Ping Test (1000ms timeout)
                    try
                    {
                        using (Ping p = new Ping())
                        {
                            PingReply reply = p.Send(targetHost, 1000);
                            if (reply.Status == IPStatus.Success)
                            {
                                pingStatus = string.Format("ONLINE (Ping: {0} ms)", reply.RoundtripTime);
                            }
                            else
                            {
                                pingStatus = string.Format("OFFLINE / UNREACHABLE ({0})", reply.Status);
                            }
                        }
                    }
                    catch
                    {
                        pingStatus = "OFFLINE / UNREACHABLE (Host unreachable or ICMP blocked by firewall)";
                    }

                                        infoText = string.Format(
                        "CALLER COMPUTER NETWORK & CONNECTIVITY STATUS\r\n" +
                        "----------------------------------------\r\n" +
                        "Caller Host / IP:     {0}\r\n" +
                        "Network Reachability: {1}\r\n" +
                        "Resolved IPv4:        {2}\r\n\r\n" +
                        "Active and disconnected user sessions on this machine are queried on the right panel.",
                        computerName,
                        pingStatus,
                        resolvedIp);
                }
                catch (Exception ex)
                {
                    infoText = string.Format("Computer: {0}\r\n\r\nNotice: {1}", computerName, ex.Message);
                }

                this.BeginInvoke((Action)(() =>
                {
                    _rtbComputerDetails.Text = infoText;
                }));
            });
        }

        // -------------------------------------------------------------
        // QUERY SESSIONS VIA QUSER (WITH 10-SECOND RPC TIMEOUT)
        // -------------------------------------------------------------
        private void QueryQUserAsync(string computerName)
        {
            if (string.IsNullOrEmpty(computerName)) return;

            _lvSessions.Items.Clear();
            _btnLogoffUser.Enabled = false;
            _progressBar.Visible = true;
            _statusLabel.Text = string.Format("Querying active and disconnected sessions on {0} via QUSER (10s timeout)...", computerName);

            ThreadPool.QueueUserWorkItem(state =>
            {
                List<QUserSessionItem> sessions = new List<QUserSessionItem>();
                string error = null;

                try
                {
                    string targetAccount = _selectedUser != null ? _selectedUser.SamAccountName : "";

                    ProcessStartInfo psi = new ProcessStartInfo();
                        psi.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "quser.exe");
                        psi.Arguments = "/server:" + computerName;
                        psi.CreateNoWindow = true;
                        psi.UseShellExecute = false;
                        psi.RedirectStandardOutput = true;
                        psi.RedirectStandardError = true;

                        using (Process proc = Process.Start(psi))
                        {
                            if (!proc.WaitForExit(10000))
                            {
                                try { proc.Kill(); } catch { }
                                error = "QUSER timed out after 10 seconds. Workstation may be offline, in sleep mode, or RPC/Firewall is blocking remote administration.";
                            }
                            else
                            {
                                string output = proc.StandardOutput.ReadToEnd();
                                string stderr = proc.StandardError.ReadToEnd();
                                string combined = output + "\r\n" + stderr;

                                if (Regex.IsMatch(combined, "(?i)no user exists|no session exists|there are no users"))
                                {
                                    // 0 sessions
                                }
                                else
                                {
                                    string[] lines = output.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                                    foreach (string line in lines)
                                    {
                                        string trimmed = line.Trim();
                                        if (trimmed.StartsWith("USERNAME", StringComparison.OrdinalIgnoreCase)) continue;
                                        if (trimmed.StartsWith(">")) trimmed = trimmed.Substring(1).Trim();

                                        Match m = Regex.Match(trimmed, @"^\s*(?<user>\S+)\s+(?<sess>\S+)?\s+(?<id>\d+)\s+(?<state>\S+)\s+(?<idle>\S+)\s*(?<logon>.*)$");
                                        if (m.Success)
                                        {
                                            string uName = m.Groups["user"].Value;
                                            bool isTarget = !string.IsNullOrEmpty(targetAccount) && string.Equals(uName, targetAccount, StringComparison.OrdinalIgnoreCase);

                                            sessions.Add(new QUserSessionItem
                                            {
                                                UserName = uName,
                                                SessionName = m.Groups["sess"].Value,
                                                SessionId = m.Groups["id"].Value,
                                                State = m.Groups["state"].Value,
                                                IdleTime = m.Groups["idle"].Value,
                                                LogonTime = m.Groups["logon"].Value.Trim(),
                                                IsTargetUser = isTarget
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                catch (Exception ex)
                {
                    error = ex.Message;
                }

                this.BeginInvoke((Action)(() =>
                {
                    _progressBar.Visible = false;
                    _lvSessions.Items.Clear();

                    if (error != null)
                    {
                        _statusLabel.Text = string.Format("QUSER query notice for {0}: {1}", computerName, error);
                        ListViewItem errItem = new ListViewItem("(Sessions unavailable)");
                        errItem.SubItems.Add("");
                        errItem.SubItems.Add("Offline");
                        errItem.SubItems.Add("");
                        errItem.SubItems.Add(error);
                        errItem.SubItems.Add("");
                        errItem.ForeColor = Color.DimGray;
                        _lvSessions.Items.Add(errItem);
                        return;
                    }

                    foreach (var s in sessions)
                    {
                        ListViewItem item = new ListViewItem(s.UserName);
                        item.SubItems.Add(s.SessionId);
                        item.SubItems.Add(s.State);
                        item.SubItems.Add(s.IdleTime);
                        item.SubItems.Add(s.LogonTime);
                        item.SubItems.Add(s.IsTargetUser ? "TARGET" : "");
                        item.Tag = s;

                        if (s.IsTargetUser)
                        {
                            item.BackColor = Color.FromArgb(254, 226, 226); // red-100 highlight target user
                            item.ForeColor = Color.FromArgb(153, 27, 27);
                            item.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
                        }

                        _lvSessions.Items.Add(item);
                    }

                    _statusLabel.Text = string.Format("QUSER returned {0} session(s) on {1}.", sessions.Count, computerName);
                }));
            });
        }

        // -------------------------------------------------------------
        // SESSION SELECTION & LOGOFF
        // -------------------------------------------------------------
        private void SessionSelectionChanged(object sender, EventArgs e)
        {
            if (_lvSessions.SelectedItems.Count == 0)
            {
                _selectedSession = null;
                _btnLogoffUser.Enabled = false;
                _btnLogoffUser.Text = "LOG OFF USER SESSION";
                return;
            }

            _selectedSession = _lvSessions.SelectedItems[0].Tag as QUserSessionItem;
            if (_selectedSession == null) return;

            // Allow logging off ANY selected user session (e.g. shared workstation session, contractor, or stale disconnected session)
            _btnLogoffUser.Enabled = true;
            _btnLogoffUser.Text = string.Format("LOG OFF '{0}'", _selectedSession.UserName.ToUpper());
            _statusLabel.Text = string.Format("Session {0} for user '{1}' on {2} selected (State: {3}). Click button below to log off this session.",
                _selectedSession.SessionId, _selectedSession.UserName, _selectedComputer, _selectedSession.State);
        }

        private void LogoffUserClick(object sender, EventArgs e)
        {
            if (_selectedSession == null || string.IsNullOrEmpty(_selectedComputer)) return;

            string confirmMsg = string.Format(
                "REMOTE LOGOFF\r\n\r\n" +
                "User:        {0}\r\n" +
                "Computer:    {1}\r\n" +
                "Session ID:  {2}\r\n" +
                "State:       {3}\r\n\r\n" +
                "This will immediately terminate the user's session on the remote computer.\r\n" +
                "Are you sure you want to proceed?",
                _selectedSession.UserName, _selectedComputer, _selectedSession.SessionId, _selectedSession.State);

            DialogResult confirm = MessageBox.Show(confirmMsg, "CONFIRM REMOTE LOGOFF", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            try
            {
                if (_domainInfoLabel.Text.Contains("DEMO MODE"))
                {
                    MessageBox.Show(string.Format("User '{0}' logged off from {1} successfully! [Demo Mode]", _selectedSession.UserName, _selectedComputer), "Logoff Successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    _lvSessions.Items.Clear();
                    _btnLogoffUser.Enabled = false;
                    return;
                }

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "logoff.exe");
                psi.Arguments = string.Format("{0} /server:{1}", _selectedSession.SessionId, _selectedComputer);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;

                using (Process proc = Process.Start(psi))
                {
                    proc.WaitForExit();
                    if (proc.ExitCode == 0)
                    {
                        MessageBox.Show(string.Format("User '{0}' (Session {1}) has been logged off from {2}.", _selectedSession.UserName, _selectedSession.SessionId, _selectedComputer), "Logoff Successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        QueryQUserAsync(_selectedComputer);
                    }
                    else
                    {
                        MessageBox.Show(string.Format("logoff.exe returned exit code {0}.", proc.ExitCode), "Notice", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to log off session: " + ex.Message, "Logoff Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // -------------------------------------------------------------
        // UNLOCK ACCOUNT ACTION
        // -------------------------------------------------------------
        private void UnlockAccountClick(object sender, EventArgs e)
        {
            if (_selectedUser == null) return;
            string sam = _selectedUser.SamAccountName;

            DialogResult confirm = MessageBox.Show(
                string.Format("Do you want to unlock the account '{0}' in Active Directory?\r\n\r\nThis clears the account lockout only. It does not change the password.", sam),
                "Confirm Account Unlock",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (confirm != DialogResult.Yes) return;

            try
            {
                // Native LDAP unlock: set lockoutTime = 0
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = string.Format("(&(objectCategory=person)(objectClass=user)(samaccountname={0}))", sam);
                    SearchResult res = searcher.FindOne();
                    if (res != null)
                    {
                        DirectoryEntry entry = res.GetDirectoryEntry();
                        entry.Properties["lockoutTime"].Value = 0;
                        entry.CommitChanges();

                        _selectedUser.IsCurrentlyLocked = false;
                        _currentLockedUsers.Remove(_selectedUser);
                        _historicalUsers.Insert(0, _selectedUser);
                        PopulateAccountLists();

                        DialogResult pwdChoice = MessageBox.Show(
                            string.Format("The account '{0}' has been unlocked successfully in Active Directory.\r\n\r\nWould you also like to reset this user's password now?", sam),
                            "Account Unlocked - Reset Password?",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Information);

                        if (pwdChoice == DialogResult.Yes)
                        {
                            ResetPasswordClick(null, null);
                        }
                    }
                    else
                    {
                        MessageBox.Show("Could not find user in Active Directory: " + sam, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to unlock account: " + ex.Message, "Unlock Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // -------------------------------------------------------------
        // RESET PASSWORD ACTION
        // -------------------------------------------------------------
        private void ResetPasswordClick(object sender, EventArgs e)
        {
            if (_selectedUser == null) return;
            string sam = _selectedUser.SamAccountName;

            using (PasswordPromptForm dlg = new PasswordPromptForm(sam))
            {
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    string newPassword = dlg.Password;
                    if (string.IsNullOrWhiteSpace(newPassword))
                    {
                        MessageBox.Show("The new password cannot be blank.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }

                    try
                    {
                        using (PrincipalContext ctx = new PrincipalContext(ContextType.Domain))
                        {
                            UserPrincipal user = UserPrincipal.FindByIdentity(ctx, sam);
                            if (user != null)
                            {
                                user.SetPassword(newPassword);
                                user.Save();
                                MessageBox.Show(string.Format("The password for '{0}' was reset successfully in Active Directory.", sam), "Password Reset Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                            }
                            else
                            {
                                MessageBox.Show("User principal not found: " + sam, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Failed to reset password: " + ex.Message, "Password Reset Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // REMOTE REBOOT WITH MULTI-USER SAFETY WARNING
        // -------------------------------------------------------------
        private void RebootComputerClick(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedComputer)) return;

            int activeCount = _lvSessions.Items.Count;
            string warning = string.Format(
                "REMOTE COMPUTER RESTART\r\n\r\n" +
                "You are about to restart: {0}\r\n\r\n" +
                "SAFETY CHECK:\r\n" +
                "QUSER detected {1} session(s) currently on this PC.\r\n" +
                "Rebooting will terminate work for ALL currently logged-in users.\r\n\r\n" +
                "Are you absolutely sure you want to restart {0}?",
                _selectedComputer, activeCount);

            DialogResult confirm = MessageBox.Show(warning, "CONFIRM REMOTE COMPUTER REBOOT", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "shutdown.exe");
                psi.Arguments = string.Format("/r /m \\\\{0} /t 10 /d p:4:1 /c \"Remote restart initiated by Account Lockout Helper.\"", _selectedComputer);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;

                using (Process proc = Process.Start(psi))
                {
                    proc.WaitForExit();
                    if (proc.ExitCode == 0)
                    {
                        MessageBox.Show(string.Format("Reboot command sent to {0} (10-second countdown initiated).", _selectedComputer), "Reboot Dispatched", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        _lvSessions.Items.Clear();
                    }
                    else
                    {
                        MessageBox.Show(string.Format("Shutdown command returned exit code {0}.", proc.ExitCode), "Notice", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to dispatch reboot command: " + ex.Message, "Reboot Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // -------------------------------------------------------------
        // CLIPBOARD COPY HELPERS
        // -------------------------------------------------------------
        private void CopyToClipboard(string text, string successMsg)
        {
            if (string.IsNullOrEmpty(text)) return;
            try
            {
                Clipboard.SetText(text);
                _statusLabel.Text = successMsg;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Clipboard error: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void CopyFullTicket()
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            sb.AppendLine("ACCOUNT LOCKOUT TICKET SUMMARY");
            sb.AppendLine("=============================");
            sb.AppendLine(string.Format("Generated: {0:yyyy-MM-dd HH:mm:ss}", DateTime.Now));
            sb.AppendLine();
            sb.AppendLine(_rtbAccountDetails.Text);
            sb.AppendLine();
            sb.AppendLine("=============================");
            sb.AppendLine("COMPUTER / SESSION INFORMATION");
            sb.AppendLine("=============================");
            sb.AppendLine(_rtbComputerDetails.Text);
            sb.AppendLine();
            sb.AppendLine("=============================");
            sb.AppendLine("CURRENT SESSION LIST (QUSER)");
            sb.AppendLine("=============================");
            if (_lvSessions.Items.Count == 0)
            {
                sb.AppendLine("No session rows currently shown.");
            }
            else
            {
                foreach (ListViewItem item in _lvSessions.Items)
                {
                    sb.AppendLine(string.Format("{0} | Session {1} | {2} | Idle {3} | Logon {4} | {5}",
                        item.SubItems[0].Text, item.SubItems[1].Text, item.SubItems[2].Text,
                        item.SubItems[3].Text, item.SubItems[4].Text, item.SubItems[5].Text));
                }
            }

            CopyToClipboard(sb.ToString(), "Full investigation ticket copied to clipboard.");
        }

        private string NormalizeAccount(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";
            string s = raw.Trim();
            if (s.Contains("\\")) s = s.Substring(s.LastIndexOf('\\') + 1);
            if (s.Contains("@")) s = s.Substring(0, s.IndexOf('@'));
            return s.Trim();
        }

        private string NormalizeComputer(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";
            string s = raw.Trim();
            if (s.StartsWith("\\\\")) s = s.Substring(2);
            if (s == "-" || s == "?" || s.Equals("unknown", StringComparison.OrdinalIgnoreCase)) return "";
            return s;
        }

        private string DecodeLogonType(string type)
        {
            if (string.IsNullOrEmpty(type)) return "";
            string t = type.Trim();
            switch (t)
            {
                case "2": return "Type 2 (Interactive Console)";
                case "3": return "Type 3 (Network / Wi-Fi / SMB)";
                case "4": return "Type 4 (Batch Job)";
                case "5": return "Type 5 (Windows Service)";
                case "7": return "Type 7 (Unlock Workstation)";
                case "8": return "Type 8 (Network Cleartext)";
                case "9": return "Type 9 (NewCredentials)";
                case "10": return "Type 10 (Remote Desktop / RDP)";
                case "11": return "Type 11 (Cached Interactive)";
                default: return "Type " + t;
            }
        }

        private string DecodeSubStatus(string status)
        {
            if (string.IsNullOrEmpty(status)) return "";
            string s = status.Trim();
            if (s.Equals("0xC000006A", StringComparison.OrdinalIgnoreCase) || s.Equals("3221225578", StringComparison.OrdinalIgnoreCase))
                return "0xC000006A (Bad Password)";
            if (s.Equals("0xC0000234", StringComparison.OrdinalIgnoreCase) || s.Equals("3221226036", StringComparison.OrdinalIgnoreCase))
                return "0xC0000234 (Account Locked Out)";
            if (s.Equals("0xC0000072", StringComparison.OrdinalIgnoreCase) || s.Equals("3221225586", StringComparison.OrdinalIgnoreCase))
                return "0xC0000072 (Account Disabled)";
            if (s.Equals("0xC0000193", StringComparison.OrdinalIgnoreCase) || s.Equals("3221225875", StringComparison.OrdinalIgnoreCase))
                return "0xC0000193 (Account Expired)";
            if (s.Equals("0xC0000071", StringComparison.OrdinalIgnoreCase) || s.Equals("3221225585", StringComparison.OrdinalIgnoreCase))
                return "0xC0000071 (Password Expired)";
            if (s.Equals("0xC0000224", StringComparison.OrdinalIgnoreCase) || s.Equals("3221226020", StringComparison.OrdinalIgnoreCase))
                return "0xC0000224 (User Must Change Password)";
            if (s.Equals("0x18", StringComparison.OrdinalIgnoreCase) || s.Equals("24", StringComparison.OrdinalIgnoreCase))
                return "0x18 (Bad Password / Pre-Auth Failed)";
            if (s.Equals("0x12", StringComparison.OrdinalIgnoreCase) || s.Equals("18", StringComparison.OrdinalIgnoreCase))
                return "0x12 (Account Locked)";
            if (s.Equals("0x17", StringComparison.OrdinalIgnoreCase) || s.Equals("23", StringComparison.OrdinalIgnoreCase))
                return "0x17 (Password Expired)";
            return s;
        }

        private string GetNamedEventData(EventRecord record, string dataName)
        {
            if (record == null) return null;
            try
            {
                string xml = record.ToXml();
                if (!string.IsNullOrEmpty(xml))
                {
                    Match m = Regex.Match(xml, string.Format(@"<Data\s+Name=['""]{0}['""]>([^<]*)</Data>", Regex.Escape(dataName)), RegexOptions.IgnoreCase);
                    if (m.Success) return m.Groups[1].Value.Trim();
                }
            }
            catch { }
            return null;
        }
    }

    // -------------------------------------------------------------
    // PASSWORD PROMPT DIALOG
    // -------------------------------------------------------------
    public class PasswordPromptForm : Form
    {
        private TextBox _txtPassword;
        private CheckBox _chkShow;
        public string Password { get { return _txtPassword.Text; } }

        public PasswordPromptForm(string accountName)
        {
            this.Text = "Set New Password - " + accountName;
            this.Size = new Size(460, 195);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterParent;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Font = new Font("Segoe UI", 9F);

            Label lbl = new Label();
            lbl.Text = string.Format("Enter the new password to set for '{0}':", accountName);
            lbl.Location = new Point(16, 16);
            lbl.AutoSize = true;
            this.Controls.Add(lbl);

            _txtPassword = new TextBox();
            _txtPassword.Location = new Point(18, 44);
            _txtPassword.Size = new Size(408, 24);
            _txtPassword.UseSystemPasswordChar = true;
            this.Controls.Add(_txtPassword);

            _chkShow = new CheckBox();
            _chkShow.Text = "Show password characters";
            _chkShow.Location = new Point(18, 76);
            _chkShow.AutoSize = true;
            _chkShow.CheckedChanged += (s, e) => _txtPassword.UseSystemPasswordChar = !_chkShow.Checked;
            this.Controls.Add(_chkShow);

            Button btnOk = new Button();
            btnOk.Text = "OK";
            btnOk.DialogResult = DialogResult.OK;
            btnOk.Location = new Point(255, 115);
            btnOk.Size = new Size(80, 32);
            this.Controls.Add(btnOk);

            Button btnCancel = new Button();
            btnCancel.Text = "Cancel";
            btnCancel.DialogResult = DialogResult.Cancel;
            btnCancel.Location = new Point(345, 115);
            btnCancel.Size = new Size(80, 32);
            this.Controls.Add(btnCancel);

            this.AcceptButton = btnOk;
            this.CancelButton = btnCancel;
        }
    }
}
