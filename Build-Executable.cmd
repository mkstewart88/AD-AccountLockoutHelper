@echo off
setlocal
title Build Account Lockout Helper Executable
cd /d "%~dp0"

echo ======================================================================
echo Domain Lockout Helper - Executable Compiler
echo ======================================================================
echo.

:: 1. Search for 64-bit and 32-bit C# Compiler (csc.exe)
set "CSC="

if exist "%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not defined CSC if exist "%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not defined CSC if exist "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not defined CSC if exist "%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not defined CSC if exist "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" set "CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not defined CSC if exist "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" set "CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"

if not defined CSC goto :NO_CSC
if not exist "%~dp0Program-Code.cs" goto :NO_SOURCE

echo Found C# Compiler:
echo %CSC%
echo.
echo Compiling Program-Code.cs into AccountLockoutHelper.exe...
echo.

"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /out:"%~dp0AccountLockoutHelper.exe" /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.DirectoryServices.dll /r:System.DirectoryServices.AccountManagement.dll "%~dp0Program-Code.cs"

if %ERRORLEVEL% NEQ 0 goto :BUILD_FAILED

echo.
echo ======================================================================
echo [SUCCESS] AccountLockoutHelper.exe was successfully created!
echo Location: %~dp0AccountLockoutHelper.exe
echo ======================================================================
echo.

set /p RUN_APP="Launch AccountLockoutHelper.exe now? (Y/N): "
if /i "%RUN_APP%"=="Y" (
    echo Starting AccountLockoutHelper.exe...
    start "" "%~dp0AccountLockoutHelper.exe"
)

echo.
echo Press any key to close this window.
pause >nul
exit /b 0

:NO_CSC
echo.
echo [ERROR] Could not find the Microsoft .NET Framework C# compiler (csc.exe).
echo Please ensure Microsoft .NET Framework 4.0 or higher is installed.
echo Expected at: %SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
echo.
pause
exit /b 1

:NO_SOURCE
echo.
echo [ERROR] Program-Code.cs source file was not found in:
echo %~dp0
echo.
pause
exit /b 1

:BUILD_FAILED
echo.
echo [ERROR] Compilation failed with error code %ERRORLEVEL%.
echo Please see the compiler messages above.
echo.
pause
exit /b %ERRORLEVEL%
