# Defender for Endpoint - internet-facing devices

## Query Information

### Description

Use these queries to identify internet-facing endpoints, review exposed ports and protocols, and investigate devices observed by external scans.

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1190 | Initial Access: Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ |
| T1133 | Initial Access: External Remote Services | https://attack.mitre.org/techniques/T1133/ |
| T1021.001 | Lateral Movement: Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |
| T1021.002 | Lateral Movement: Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ |
| T1595 | Reconnaissance: Active Scanning | https://attack.mitre.org/techniques/T1595/ |

#### References

- [Discovering internet-facing devices using Microsoft Defender for Endpoint](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/discovering-internet-facing-devices-using-microsoft-defender-for/ba-p/3778975)

### KQL

```kql
DeviceInfo
| where IsInternetFacing == true
| extend InternetFacingInfo = AdditionalFields
| extend AF = parse_json(tostring(AdditionalFields))
| extend
    InternetFacingLastSeen = todatetime(AF.InternetFacingLastSeen),
    InternetFacingLocalIp = tostring(AF.InternetFacingLocalIp),
    InternetFacingLocalPort = toint(AF.InternetFacingLocalPort),
    InternetFacingPublicScannedIp = tostring(AF.InternetFacingPublicScannedIp),
    InternetFacingPublicScannedPort = toint(AF.InternetFacingPublicScannedPort),
    InternetFacingReason = tostring(AF.InternetFacingReason),
    InternetFacingTransportProtocol = tostring(AF.InternetFacingTransportProtocol)
| summarize
    Ports = make_set(InternetFacingPublicScannedPort),
    LocalPorts = make_set(InternetFacingLocalPort),
    Reasons = make_set(InternetFacingReason),
    LocalIPs = make_set(InternetFacingLocalIp),
    Protocols = make_set(InternetFacingTransportProtocol),
    LastSeen = max(InternetFacingLastSeen)
    by DeviceName
| order by LastSeen desc
```

Devices detected by an external scan

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where ActionType == "InboundInternetScanInspected"
| extend AF = parse_json(tostring(AdditionalFields))
| extend
    PublicScannedIp = tostring(AF.PublicScannedIp),
    PublicScannedPort = toint(AF.PublicScannedPort)
| summarize arg_max(TimeGenerated, *) by DeviceId
| project
    TimeGenerated,
    DeviceName,
    DeviceId,
    ActionType,
    PublicScannedIp,
    PublicScannedPort
```

Devices detected by an external scan with IP geolocation information

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where ActionType == "InboundInternetScanInspected"
| extend AF = parse_json(tostring(AdditionalFields))
| extend
    PublicScannedIp = tostring(AF.PublicScannedIp),
    PublicScannedPort = toint(AF.PublicScannedPort)
| where isnotempty(PublicScannedIp)
| extend GeoInfo = geo_info_from_ip_address(PublicScannedIp)
| extend
    PublicScannedCountry = tostring(GeoInfo.country),
    PublicScannedState = tostring(GeoInfo.state),
    PublicScannedCity = tostring(GeoInfo.city),
    PublicScannedLatitude = todouble(GeoInfo.latitude),
    PublicScannedLongitude = todouble(GeoInfo.longitude)
| summarize arg_max(TimeGenerated, *) by DeviceId
| project
    TimeGenerated,
    DeviceName,
    DeviceId,
    ActionType,
    PublicScannedIp,
    PublicScannedPort,
    PublicScannedCountry,
    PublicScannedState,
    PublicScannedCity
//    PublicScannedLatitude,
    // PublicScannedLongitude
| order by TimeGenerated desc
```




SMB

```kql
DeviceInfo
| where IsInternetFacing == true
| extend InternetFacingInfo = AdditionalFields
| extend AF = parse_json(tostring(AdditionalFields))
| extend
    InternetFacingLastSeen = todatetime(AF.InternetFacingLastSeen),
    InternetFacingLocalIp = tostring(AF.InternetFacingLocalIp),
    InternetFacingLocalPort = toint(AF.InternetFacingLocalPort),
    InternetFacingPublicScannedIp = tostring(AF.InternetFacingPublicScannedIp),
    InternetFacingPublicScannedPort = toint(AF.InternetFacingPublicScannedPort),
    InternetFacingReason = tostring(AF.InternetFacingReason),
    InternetFacingTransportProtocol = tostring(AF.InternetFacingTransportProtocol)
| where InternetFacingLocalPort in (139, 445)
| project
    TimeGenerated,
    DeviceName,
    PublicIP,
    InternetFacingLastSeen,
    InternetFacingLocalIp,
    InternetFacingLocalPort,
    InternetFacingPublicScannedIp,
    InternetFacingPublicScannedPort,
    InternetFacingReason,
    InternetFacingTransportProtocol
```

RDP

```kql
DeviceInfo
| where IsInternetFacing == true
| extend AF = parse_json(tostring(AdditionalFields))
| extend
    InternetFacingLastSeen = todatetime(AF.InternetFacingLastSeen),
    InternetFacingLocalIp = tostring(AF.InternetFacingLocalIp),
    InternetFacingLocalPort = toint(AF.InternetFacingLocalPort),
    InternetFacingPublicScannedIp = tostring(AF.InternetFacingPublicScannedIp),
    InternetFacingPublicScannedPort = toint(AF.InternetFacingPublicScannedPort),
    InternetFacingReason = tostring(AF.InternetFacingReason),
    InternetFacingTransportProtocol = tostring(AF.InternetFacingTransportProtocol)
| where InternetFacingLocalPort == 3389
| project
    TimeGenerated,
    DeviceName,
    PublicIP,
    InternetFacingLastSeen,
    InternetFacingLocalIp,
    InternetFacingLocalPort,
    InternetFacingPublicScannedIp,
    InternetFacingPublicScannedPort,
    InternetFacingReason,
    InternetFacingTransportProtocol
```

ExternalNetworkConnection (still testing....)

```kql
let InternetFacingDevices =
DeviceInfo
| where IsInternetFacing == true
| extend AF = parse_json(tostring(AdditionalFields))
| extend
    InternetFacingLastSeen = todatetime(AF.InternetFacingLastSeen),
    InternetFacingLocalIp = tostring(AF.InternetFacingLocalIp),
    InternetFacingLocalPort = toint(AF.InternetFacingLocalPort),
    InternetFacingPublicScannedIp = tostring(AF.InternetFacingPublicScannedIp),
    InternetFacingPublicScannedPort = toint(AF.InternetFacingPublicScannedPort),
    InternetFacingReason = tostring(AF.InternetFacingReason),
    InternetFacingTransportProtocol = tostring(AF.InternetFacingTransportProtocol)
| where InternetFacingReason == "ExternalNetworkConnection"
| project
    DeviceId,
    DeviceName,
    TimeGenerated,
    InternetFacingLastSeen,
    InternetFacingLocalIp,
    InternetFacingLocalPort,
    InternetFacingPublicScannedIp,
    InternetFacingPublicScannedPort,
    InternetFacingReason,
    InternetFacingTransportProtocol;
let PublicNetworkConnections =
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteIPType == "Public"
| project
    DeviceId,
    DeviceName,
    NetworkTimestamp = TimeGenerated,
    LocalIP,
    LocalPort,
    LocalIPType,
    RemoteIP,
    RemotePort,
    RemoteIPType,
    ActionType,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName;
InternetFacingDevices
| join kind=leftouter PublicNetworkConnections on DeviceId
| where tostring(LocalIP) == InternetFacingLocalIp
| where toint(LocalPort) == InternetFacingLocalPort
| project
    TimeGenerated,
    NetworkTimestamp,
    DeviceName,
    InternetFacingPublicScannedIp,
    InternetFacingPublicScannedPort,
    InternetFacingLocalIp,
    InternetFacingLocalPort,
    InternetFacingTransportProtocol,
    LocalIP,
    LocalPort,
    RemoteIP,
    RemotePort,
    RemoteIPType,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine
| order by NetworkTimestamp desc
```

Combine IP address with TI in Sentinel

```kql
DeviceInfo
| where IsInternetFacing
| extend InternetFacingInfo = AdditionalFields 
| extend InternetFacingLastSeen = tostring(AdditionalFields.InternetFacingLastSeen)
| extend InternetFacingLocalIp = tostring(AdditionalFields.InternetFacingLocalIp)
| extend InternetFacingLocalPort = tostring(AdditionalFields.InternetFacingLocalPort)
| extend InternetFacingPublicScannedIp = tostring(AdditionalFields.InternetFacingPublicScannedIp)
| extend InternetFacingPublicScannedPort = tostring(AdditionalFields.InternetFacingPublicScannedPort)
| extend InternetFacingReason = tostring(AdditionalFields.InternetFacingReason)
| extend InternetFacingTransportProtocol = tostring(AdditionalFields.InternetFacingTransportProtocol)
| where InternetFacingReason == "ExternalNetworkConnection"
| join kind=leftouter  (DeviceNetworkEvents
| where RemoteIPType == "Public"
| distinct DeviceName, LocalIP, LocalPort, LocalIPType, RemoteIP, RemoteIPType, RemotePort, ActionType,InitiatingProcessFolderPath
)
on $left. DeviceName == $right. DeviceName
| where LocalIP contains InternetFacingLocalIp
| where LocalPort == InternetFacingLocalPort
| project-keep TimeGenerated, DeviceName,PublicIP, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType, ActionType,  InternetFacing*, InitiatingProcessFolderPath 
| project-away InternetFacingInfo
| join kind=innerunique  (ThreatIntelligenceIndicator
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true
    | where isnotempty(NetworkIP)
        or isnotempty(EmailSourceIpAddress)
        or isnotempty(NetworkDestinationIP)
        or isnotempty(NetworkSourceIP)
    | extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity))
    on $left. RemoteIP == $right. TI_ipEntity
```
