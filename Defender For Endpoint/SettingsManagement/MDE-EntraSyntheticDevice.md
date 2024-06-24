# Microsoft Defender for Endpoint - Security Settings Management - Entra ID Synthetic Device actions

## Query Information

### Description

Use the below queries to find events related to MDE Security Settings management. 

#### References

### Sentinel

The below query shows when MDE signals Intune after onbarding/offbaording MDE to create/delete a synthetic device object in Entra ID

```kql
AuditLogs
| where Identity == "Microsoft Intune"
| where OperationName has_any ('Delete device','Add device')
| extend displayName = tostring(TargetResources[0].displayName)
| extend id = tostring(TargetResources[0].id)
| extend DeviceId = tostring(AdditionalDetails[0].value)
```

