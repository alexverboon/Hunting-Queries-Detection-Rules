# Defender for Endpoint - WSL Host and Version

## Query Information

### Description

Use the below query to identify the Windows Host and the WSL version of a Defender for endpoint enabled WSL system.

#### References

### Microsoft 365 Defender

```kql
DeviceInfo
| where OSPlatform == 'Linux' and isempty(HostDeviceId) != true
| summarize arg_max(TimeGenerated,*) by DeviceId
| project TimeGenerated, DeviceName, OSPlatform, DeviceId, HostDeviceId
| join (DeviceInfo
| where OSPlatform contains "Windows"
| summarize arg_max(TimeGenerated,*) by DeviceId
| extend HostOSPlatform = OSPlatform
| extend HostDeviceName = DeviceName
| extend HostDeviceId = DeviceId)
on $left. HostDeviceId == $right. HostDeviceId
| project TimeGenerated, DeviceName, OSPlatform, DeviceId, HostDeviceId, HostDeviceName, HostOSPlatform
| join (DeviceProcessEvents
| where InitiatingProcessFileName == 'wsl.exe'
| summarize arg_max(TimeGenerated,*) by DeviceId
| project InitiatingProcessVersionInfoProductVersion, InitiatingProcessVersionInfoFileDescription, InitiatingProcessFileName, DeviceId)
on $left.HostDeviceId == $right.DeviceId
```

