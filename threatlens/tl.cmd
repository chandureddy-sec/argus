@echo off
rem ThreatLens launcher: "tl up" (cmd) or ".\tl up" (PowerShell). See scripts\stack.ps1.
rem -ExecutionPolicy Bypass applies to this one script run only; system policy is unchanged.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stack.ps1" %*
exit /b %ERRORLEVEL%
