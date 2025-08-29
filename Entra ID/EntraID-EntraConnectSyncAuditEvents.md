# Entra ID - Microsoft Entra Connect Sync Audit Events

## Query Information

### Description

Use the below query to parse the Entra Connect Sync Audit Logs.
**Note!** You must forward the Event Logs outlined in the below referenced article to your Log Analytics Workspace.

#### References

- [Audit administrator events in Microsoft Entra Connect Sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/admin-audit-logging)

### Author

- **Alex Verboon**

## Sentinel

```kql
SecurityEvent
| where EventSourceName == "Entra Connect Admin Actions"
| extend xml = parse_xml(tostring(EventData))
| extend data_text = coalesce(
        tostring(xml.EventData.Data),
        tostring(xml["EventData"]["Data"]["#text"])
    )
| where isnotempty(data_text)
| extend j = todynamic(data_text)
| extend
    ActionType      = tostring(j.ActionType),
    AuditEventType  = tostring(j.AuditEventType),
    Category        = tostring(j.Category),
    Name            = tostring(j.Name),
    Status          = tostring(j.Status),
    EventJsonTime   = tostring(j.Timestamp),
    User            = tostring(j.User),
    Details         = tostring(j.Details)
| project TimeGenerated, EventID, Name, ActionType, Status, User, EventJsonTime, Details
| order by TimeGenerated desc
```
