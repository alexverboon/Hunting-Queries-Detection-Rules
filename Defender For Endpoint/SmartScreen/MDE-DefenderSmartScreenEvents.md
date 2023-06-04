# Smart Screen Events

## Query Information

### Description

Use the following queries to find Windows Defender SmartScreen events.

#### References

- [Protect your network](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide)
- [Microsoft Defender SmartScreen](https://learn.microsoft.com/de-de/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/)

### Microsoft 365 Defender

A user has overridden a SmartScreen warning and continued to open an untrusted app or a low-reputation URL.

```kql
DeviceEvents
 | where ActionType == 'SmartScreenUserOverride' 
```

Defender SmartScreen Browser Warnings

```kql
DeviceEvents
| where ActionType == "SmartScreenUrlWarning"
| extend data = parse_json(AdditionalFields)
| extend Experience = parse_json(data).Experience
| project Timestamp, DeviceName, ActionType, RemoteUrl,Experience, InitiatingProcessFileName, InitiatingProcessAccountUpn
```

```kql
DeviceEvents 
| where ActionType == "SmartScreenUrlWarning"
| extend ParsedFields=parse_json(AdditionalFields)
| project DeviceName, ActionType, Timestamp, RemoteUrl, InitiatingProcessFileName, Experience=tostring(ParsedFields.Experience)
| where Experience == "CustomPolicy"
```

Defender SmartScreen App Warnings

```kql
DeviceEvents
| where ActionType == "SmartScreenAppWarning"
| extend data = parse_json(AdditionalFields)
| extend Experience = parse_json(data).Experience
| project Timestamp, DeviceName, ActionType, FileName,Experience, InitiatingProcessFileName, InitiatingProcessAccountUpn
```

Defender SmartScreen and Network Protection

```kql
DeviceEvents
| where ActionType in ("SmartScreenUrlWarning","SmartScreenUserOverride","SmartScreenAppWarning","ExploitGuardNetworkProtectionAudited","ExploitGuardNetworkProtectionBlocked")
// | distinct ActionType,InitiatingProcessFileName, RemoteUrl
| extend data = parse_json(AdditionalFields)
| extend Experience = parse_json(data).Experience
| extend ApplicationName = parse_json(data).Experience
| extend ResponseCategory = parse_json(data).ResponseCategory
```



