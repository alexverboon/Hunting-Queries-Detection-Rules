# Network Protection

## Query Information

### Description

Use the below queries to retrieve network protection events

#### References

- [Protect your network](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide)

### Microsoft 365 Defender

```kql
DeviceEvents 
| where ActionType in ('ExploitGuardNetworkProtectionAudited','ExploitGuardNetworkProtectionBlocked')
```

```kql
DeviceEvents 
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| extend JsonOut = parse_json(AdditionalFields)
| sort by Timestamp desc 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,  
         RemoteUrl, InitiatingProcessCommandLine,
         JsonOut.IsAudit,JsonOut.Uri
```

Defender Network Protection - blocked - system account

```kql
DeviceEvents
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| where InitiatingProcessAccountName == "system"
| extend ResponseCat = parse_json(AdditionalFields).ResponseCategory
| extend Uri = parse_json(AdditionalFields).DisplayName
| project Timestamp, DeviceName,DeviceId, RemoteUrl, ResponseCat, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
DeviceEvents 
| where ActionType == "ExploitGuardNetworkProtectionBlocked" 
| extend data = parse_json(AdditionalFields)
| extend IsAudit = tostring(data.IsAudit)
| extend ResponseCategory = tostring(data.ResponseCategory)
| extend Uri = replace('"',"",tostring(split(tostring(parse_json(AdditionalFields).DisplayName),"=")[1]))
| project Timestamp, DeviceName,IsAudit, ResponseCategory, Uri
```

Defender Network Protection

```kql
DeviceEvents
| where ActionType in ('ExploitGuardNetworkProtectionAudited','ExploitGuardNetworkProtectionBlocked')
| distinct ActionType,InitiatingProcessFileName, RemoteUrl
```

Defender SmartScreen

```kql
DeviceEvents
| where ActionType in ("SmartScreenUrlWarning","SmartScreenUserOverride")
| distinct ActionType,InitiatingProcessFileName, RemoteUrl
```

Defender SmartScreen  and Network Protection

```kql
DeviceEvents
| where ActionType in ("SmartScreenUrlWarning","SmartScreenUserOverride","ExploitGuardNetworkProtectionAudited","ExploitGuardNetworkProtectionBlocked")
| distinct ActionType,InitiatingProcessFileName, RemoteUrl

```

Defender SmartScreen  and Network Protection

```kql
DeviceEvents
| where ActionType in ("SmartScreenUrlWarning","SmartScreenUserOverride","ExploitGuardNetworkProtectionAudited","ExploitGuardNetworkProtectionBlocked")
 | distinct ActionType, AdditionalFields, RemoteUrl
| extend data = parse_json(AdditionalFields)
| extend Category = iff(ActionType == "SmartScreenUrlWarning",tostring(parse_json(data).Experience),
                    iff(ActionType == "ExploitGuardNetworkProtectionAudited",tostring(parse_json(data).ResponseCategory),
                    iff(ActionType == "ExploitGuardNetworkProtectionBlocked",tostring(parse_json(data).ResponseCategory),
                    iff(ActionType == "SmartScreenUserOverride",tostring(parse_json(data).ResponseCategory),""))))
| extend Application = iff(ActionType == "SmartScreenUrlWarning",tostring(parse_json(data).ApplicationName),
                    iff(ActionType == "ExploitGuardNetworkProtectionAudited",RemoteUrl,
                    iff(ActionType == "ExploitGuardNetworkProtectionBlocked",RemoteUrl,
                    iff(ActionType == "SmartScreenUserOverride",tostring(parse_json(data).ApplicationName),""))))
| extend IsAudit = parse_json(data).IsAudit
| extend Allow = parse_json(data).Allow
| extend UserSid = parse_json(data).UserSid
```

```kql
AlertInfo
| join 
AlertEvidence
on $left. AlertId ==  $right.AlertId
| where Title == @"Suspicious connection blocked by network protection"
| where EntityType == @"Url"
| project Timestamp, Title, RemoteIP, RemoteUrl, AlertId
```
