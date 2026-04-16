# MDE - USB Drive detection

## Query Information


### Description

DESCRIPTION


#### References



### Microsoft 365 Defender




```kql
let MountedUSB = (
DeviceEvents
| where ActionType contains "USB"
| where Timestamp > ago(1d)
| project USBMountTime = Timestamp, DeviceName, DriveLetter = tostring(todynamic(AdditionalFields).DriveLetter));
let DistinctMounts =(
MountedUSB
| summarize max(USBMountTime) by DeviceName, DriveLetter)
| project max_USBMountTime, DeviceName, DriveLetter;
DistinctMounts
| join kind=inner (
    DeviceEvents
    | where ActionType contains "USB"
    | where Timestamp > ago(1d)
    | project DeviceName, DeviceId, Timestamp, DriveLetter = tostring(todynamic(AdditionalFields).DriveLetter), ReportId
    ) on $left.max_USBMountTime==$right.Timestamp
| project DeviceId, DeviceName, DriveLetter,Timestamp, ReportId
```

