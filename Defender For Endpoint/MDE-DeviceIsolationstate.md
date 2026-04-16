# MDE - Device - Isolation Status

## Query Information

Run the below query to identify devices that have been isolated

### Microsoft 365 Defender


```kql
DeviceInfo
| extend MitigationStatusObject = parse_json(MitigationStatus)
| extend IsolationStatus = MitigationStatusObject.Isolated
| where IsolationStatus == "true"
| summarize arg_max(Timestamp,*) by DeviceName
```

