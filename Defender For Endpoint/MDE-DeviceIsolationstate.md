# MDE - Device - Isolation Status

## Query Information


### Description

DESCRIPTION


#### References



### Microsoft 365 Defender




```kql
DeviceInfo
| extend MitigationStatusObject = parse_json(MitigationStatus)
| extend IsolationStatus = MitigationStatusObject.Isolated
| where IsolationStatus == "true"
```

