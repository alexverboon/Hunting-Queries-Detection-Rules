# Defender for Endpoint - identify devices running in Passive mode

## Query Information

### Description

identify devices running Defender Antivirus in Passive mode

#### References

### Author

- ***Microsoft***

### Microsoft Defender XDR

```kql
DeviceTvmInfoGathering
| where Timestamp > ago(3d) 
| extend AvModeTemp = AdditionalFields.AvMode 
| extend AVMode = iif(tostring(AvModeTemp) == '0', 'Active', iif(tostring(AvModeTemp) == '1', 'Passive', iif(tostring(AvModeTemp) == '4', 'EDR Blocked', 'Unknown'))) 
| summarize arg_max(LastSeenTime, *) by DeviceId 
| project DeviceName, OSPlatform, AVMode
```
