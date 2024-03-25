# Defender for Endpoint -  Windows Firewall configuration

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | https://attack.mitre.org/techniques/T1562/004/ |

### Description

Use the below queries to identify disabling or modifying Windows Defender Firewall events

#### References

- [Impair Defenses: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/)
- [Atomic Red Team - Impair Defenses: Disable or Modify System Firewall](https://atomicredteam.io/defense-evasion/T1562.004/)

### Microsoft 365 Defender

Use of netsh to disable firewall profiles

```kql
let fwoffregex = '.*advfirewall.*state off.*';
DeviceProcessEvents
| where FileName == 'netsh.exe'
| where tolower(ProcessCommandLine) matches regex fwoffregex
| project TimeGenerated, DeviceName,ProcessCommandLine
```

Use of PowerShell to configure Windows Firewall

Set-NetFirewallProfile -Profile Domain -Enabled False

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields.Command == "Set-NetFirewallProfile"
```

use of netsh to configure firewall rules

```kql
let fwoffregex = '.*advfirewall.*rule.*';
DeviceProcessEvents
| where FileName == 'netsh.exe'
| where tolower(ProcessCommandLine) matches regex fwoffregex
| project TimeGenerated, DeviceName,ProcessCommandLine
```

## Simulation

```powershell
netsh advfirewall set allprofiles state off
```

```powershell
# Disable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

```
Disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 0 /f
Cleanup
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f

```




