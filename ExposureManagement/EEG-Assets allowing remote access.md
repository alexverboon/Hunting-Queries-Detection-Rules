# External Attack Surface Protection - Assets allowing remote access

## Query Information

### Description

This query shows all discovered external assets with open ports allowing remote access, out of all discovered external assets in Defender External Attack Surface Management and then tries to correlate the asset with a device managed by Defender for Endpoint.

#### References

- [Defender External Attack Surface Management - Open Ports](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-dashboards#open-ports)
- [External Attack Surface Management initiative in Exposure Management](https://learn.microsoft.com/en-us/security-exposure-management/external-attack-surface-management-initiative)

### Author

- **Alex Verboon**

## Defender XDR

```kql
ExposureGraphNodes
| extend rawData = todynamic(NodeProperties).rawData
| where isnotnull(rawData.openPortRanges)
| extend openPortRanges = rawData.openPortRanges
| where openPortRanges has_any("21","22","23")
| join kind=leftouter (DeviceInfo
| summarize arg_max(TimeGenerated,*) by DeviceId
)
on $left. NodeName == $right. PublicIP
| extend RemoteAssetName = NodeName
| project RemoteAssetName, openPortRanges, DeviceName, PublicIP, OSPlatform, MachineGroup, ExposureLevel
```
