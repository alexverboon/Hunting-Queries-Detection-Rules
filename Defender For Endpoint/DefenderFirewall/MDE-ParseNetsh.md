# MDE - Netsh commands

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | https://attack.mitre.org/techniques/T1562/004/ |

### Description

Use the below query to parse netsh advanced firewall commands.

#### References

- [Netsh](https://attack.mitre.org/software/S0108/)
- [Use netsh advfirewall firewall instead of netsh firewall to control Windows Firewall behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior)
- [Netsh Commands for Windows Firewall](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771046(v=ws.10)?redirectedfrom=MSDN)
- [PHOSPHORUS Automates Initial Access Using ProxyShell](https://thedfirreport.com/2022/03/21/phosphorus-automates-initial-access-using-proxyshell/)
- [Atomic - Impair Defenses: Disable or Modify System Firewall](https://atomicredteam.io/defense-evasion/T1562.004/)

### Microsoft Defender XDR

```kql
let fwoffregex = '.*advfirewall.*rule.*';
DeviceProcessEvents
| where FileName == 'netsh.exe'
| extend ProcessCommandLine = tolower(ProcessCommandLine)
| where ProcessCommandLine matches regex fwoffregex
| parse ProcessCommandLine with action "advfirewall firewall" actionname:string  " " *
| parse-kv ProcessCommandLine as (name:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (program:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (protocol:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (action:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (dir:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (action:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (localport:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (enable:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (['rule name']:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (['allow program']:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (profile:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (remoteip:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv ProcessCommandLine as (group:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| project  TimeGenerated, DeviceName, AccountName, AccountDomain, InitiatingProcessCommandLine,InitiatingProcessFileName, InitiatingProcessSignatureStatus,InitiatingProcessParentFileName,InitiatingProcessIntegrityLevel,
actionname, name, program, protocol, dir, action, localport, enable, ProcessCommandLine, ['rule name'],profile, ['allow program'], remoteip, group
| extend app = parse_path(program)
```

```batch
netsh firewall set opmode disable
netsh advfirewall set allprofiles state off
```
