# Defender for Endpoint - internet-facing devices

## Query Information

### Description

Use the below queries to gather inforamtion about internet facing devcies

#### References

- [Discovering internet-facing devices using Microsoft Defender for Endpoint](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/discovering-internet-facing-devices-using-microsoft-defender-for/ba-p/3778975)

### Microsoft Sentinel

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
| summarize Ports = make_set(InternetFacingPublicScannedPort), Reason = make_set(InternetFacingReason) by DeviceName
```

Devices detected by an external scan

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where ActionType == "InboundInternetScanInspected"
| extend PublicScannedIp = tostring(AdditionalFields.PublicScannedIp)
| extend PublicScannedPort = tostring(AdditionalFields.PublicScannedPort)
| summarize arg_max(TimeGenerated,*) by DeviceId
| project TimeGenerated, DeviceName, ActionType, PublicScannedIp, PublicScannedPort
```

SMB

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
| where InternetFacingLocalPort == 139 or InternetFacingLocalPort == 445
//| summarize Ports = make_set(InternetFacingPublicScannedPort), Reason = make_set(InternetFacingReason) by DeviceName
```

RDP

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
| where InternetFacingLocalPort == 3389
//| summarize Ports = make_set(InternetFacingPublicScannedPort), Reason = make_set(InternetFacingReason) by DeviceName
```

ExternalNetworkConnection (still testing....)

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
```
