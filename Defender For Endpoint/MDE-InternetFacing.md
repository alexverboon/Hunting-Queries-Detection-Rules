# Defender for Endpoint - internet-facing devices

## Query Information

### Description

Use the below queries to gather inforamtion about internet facing devcies

#### References

- [Discovering internet-facing devices using Microsoft Defender for Endpoint](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/discovering-internet-facing-devices-using-microsoft-defender-for/ba-p/3778975)

### Microsoft 365 Defender

```kql
// query source: Microsoft
DeviceInfo 
| where Timestamp > ago(7d) 
| where IsInternetFacing 
| extend InternetFacingInfo = AdditionalFields 
| extend InternetFacingReason = extractjson("$.InternetFacingReason", InternetFacingInfo, typeof(string)), InternetFacingLocalPort = extractjson("$.InternetFacingLocalPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicPort = extractjson("$.InternetFacingScannedPublicPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicIp = extractjson("$.InternetFacingScannedPublicIp", InternetFacingInfo, typeof(string)), InternetFacingLocalIp = extractjson("$.InternetFacingLocalIp", InternetFacingInfo, typeof(string)), InternetFacingTransportProtocol=extractjson("$.InternetFacingTransportProtocol", InternetFacingInfo, typeof(string)), InternetFacingLastSeen = extractjson("$.InternetFacingLastSeen", InternetFacingInfo, typeof(datetime)) 
| summarize arg_max(Timestamp, *) by DeviceId
```

```kql
// SMB
DeviceInfo 
| where Timestamp > ago(7d) 
| where IsInternetFacing 
| extend InternetFacingInfo = AdditionalFields 
| extend InternetFacingReason = extractjson("$.InternetFacingReason", InternetFacingInfo, typeof(string)),
    InternetFacingLocalPort = extractjson("$.InternetFacingLocalPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicPort = extractjson("$.InternetFacingScannedPublicPort",
    InternetFacingInfo, typeof(int)), InternetFacingScannedPublicIp = extractjson("$.InternetFacingScannedPublicIp", InternetFacingInfo, typeof(string)),
    InternetFacingLocalIp = extractjson("$.InternetFacingLocalIp", InternetFacingInfo, typeof(string)), InternetFacingTransportProtocol=extractjson("$.InternetFacingTransportProtocol", 
    InternetFacingInfo, typeof(string)), InternetFacingLastSeen = extractjson("$.InternetFacingLastSeen", InternetFacingInfo, typeof(datetime)) 
| summarize arg_max(Timestamp, *) by DeviceId
| project
    DeviceName,
    IsInternetFacing,
    InternetFacingReason,
    InternetFacingLocalIp,
    InternetFacingLocalPort,
    InternetFacingScannedPublicIp,
    InternetFacingScannedPublicPort
| where InternetFacingLocalPort == 139 or InternetFacingLocalPort == 445

```
