# Azure Arc - Compare Azure Arc Computer Resources with Defender for Endpoint Resources

## Query Information

### Description

Use the below query to compare the Azure Arc Server Inventory with the Defender for Endpoint resources.

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
let ServerOS = dynamic(["Linux","WindowsServer2025","WindowsServer2022","WindowsServer2019","WindowsServer2016","WindowsServer2012","WindowsServer2012R2"]);
let arcservers = arg("").Resources
| where type == 'microsoft.hybridcompute/machines'
| project
  ArcComputerName = tolower(tostring(properties.osProfile.computerName)),
  ArcLocation = location,
  resourceGroup,
  subscriptionId,
  ArcOSName = tostring(properties.osName);
  DeviceInfo
    | where OSPlatform  in(ServerOS) 
  | summarize arg_max(TimeGenerated,*) by DeviceName
  | project 
MDEDeviceName = tolower(split(DeviceName,".")[0]),
  MDEOSPlatform = OSPlatform, 
  OnboardingStatus  
  | join kind=leftouter hint.remote=left (arcservers)
  on $left. MDEDeviceName == $right.ArcComputerName
  | project ArcComputerName, MDEDeviceName, ArcOSName, MDEOSPlatform, OnboardingStatus, ArcLocation, resourceGroup, subscriptionId

```
