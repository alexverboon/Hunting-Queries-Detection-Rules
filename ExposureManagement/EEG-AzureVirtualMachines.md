# Microsoft Security Exposure Management - Azure Virtual Machines

## Query Information

### Description

Use the below queries to Azure Virtual Machine information from the enterprise exposure graph.

#### References

- [Introducing Microsoft Security Exposure Management](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/introducing-microsoft-security-exposure-management/ba-p/4080907)
- [Query the enterprise exposure graph](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph)

### Microsoft Defender XDR

Retrieve Azure Virtual Machine information

```kql
ExposureGraphNodes
| where NodeLabel == @"microsoft.compute/virtualmachines"
| extend DeviceName = NodeName
| extend deviceType = parse_json(NodeProperties).rawData.deviceType
| extend lastSeen = parse_json(NodeProperties).rawData.lastSeen
| extend onboardingStatus = parse_json(NodeProperties).rawData.onboardingStatus
| extend osPlatform = parse_json(NodeProperties).rawData.osPlatform
| extend publicIP = parse_json(NodeProperties).rawData.publicIP
| extend rdpStatus_allowConnections = parse_json(NodeProperties).rawData.rdpStatus.allowConnections
| extend environmentName = parse_json(NodeProperties).rawData.environmentName
| project DeviceName, lastSeen, onboardingStatus, osPlatform, publicIP, environmentName, rdpStatus_allowConnections
```


