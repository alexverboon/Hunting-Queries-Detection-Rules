# MDE - Sense triggers PowerShell with public IP network connection

## Query Information

### Description

This query identifies Device Network connections to public IP addresses from PowerSehll, iniatiated by the MDE Sense Service.

#### References

### Microsoft Sentinel

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe"
| where InitiatingProcessParentFileName == "SenseIR.exe"
| where RemoteIPType == 'Public'
| extend ScriptPath = extract(@"([a-zA-Z]:\\[^\']+\.ps1)", 1, InitiatingProcessCommandLine)
| extend IPInfo = geo_info_from_ip_address(RemoteIP)
| project TimeGenerated, DeviceId, DeviceName, ScriptPath,InitiatingProcessCommandLine, RemoteIP, IPInfo.country
```
