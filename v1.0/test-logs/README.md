# Verified SentinelOps Test Log Guide

Download the following public detection-engineering samples from:

https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

Place downloaded files in this directory. The `.evtx` files are excluded from Git
because they are third-party GPL-licensed data; this guide remains in the repository.

## Recommended order

1. `LM_WMI_4624_4688_TargetHost.evtx`
   - 8 events
   - Contains real source addresses including `10.0.2.17`
   - Expected: addresses visible in Event Explorer

2. `phish_windows_credentials_powershell_scriptblockLog_4104.evtx`
   - 2 PowerShell script-block events
   - Expected: suspicious PowerShell alerts

3. `System_7045_namedpipe_privesc.evtx`
   - 1 Windows service-installation event
   - Expected: high-severity possible privilege-escalation alert

Use **Analyze logs**, select one `.evtx` file, and wait for parsing to complete.
The local SentinelOps service must be running through `start.ps1`.

## Additional samples

`babyshark_mimikatz_powershell.evtx` and
`Powershell_4104_MiniDumpWriteDump_Lsass.evtx` are retained for future detection-rule
development, but they do not currently produce reliable built-in alerts.

`CA_4624_4625_LogonType2_LogonProc_chrome.evtx` contains `IpAddress` values set to
`-`, which means the source address was not recorded. SentinelOps displays those values
as **Not present** and does not classify them as suspicious IPs.
