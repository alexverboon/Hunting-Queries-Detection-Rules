# Defender for Identity - Health Status updates

## Query Information

### Description

Use the below query to get information about Defender for Identity Health Status updates initiated by a user. 


#### References

- [Microsoft Defender for Identity health issues](https://learn.microsoft.com/en-us/defender-for-identity/health-alerts)


### Microsoft Sentinel



```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad == "MicrosoftDefenderForIdentity"
| where ActionType == "MonitoringAlertUpdated"
| extend ResultDescription = tostring(RawEventData.ResultDescription)
| extend UserId = tostring(RawEventData.UserId)
| project TimeGenerated, WorkLoad, ActionType,UserId, ResultDescription

```

