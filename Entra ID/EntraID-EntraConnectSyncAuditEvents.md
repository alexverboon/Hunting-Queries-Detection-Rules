# Entra ID - Microsoft Entra Connect Sync Audit Events

## Query Information

### Description

Use the below query to parse the Entra Connect Sync Audit Logs.
**Note!** You must forward the Event Logs outlined in the below referenced article to your Log Analytics Workspace.

When using the Windows Security Event Data Connector in Microsoft Sentinel, create a Data Collection Rule that collects the following events.

```kql
Application!*[System[Provider[@Name='Entra Connect Admin Actions'] and (EventID=2523 or EventID=2524 or EventID=2525 or EventID=2526)]]
Application!*[System[Provider[@Name='Entra Connect Admin Actions'] and (EventID=2503 or EventID=2504 or EventID=2505 or EventID=2506 or EventID=2507 or EventID=2508 or EventID=2509 or EventID=2510 or EventID=2511 or EventID=2512 or EventID=2513 or EventID=2514 or EventID=2515 or EventID=2516 or EventID=2517 or EventID=2518 or EventID=2519 or EventID=2520)]]
Application!*[System[Provider[@Name='Entra Connect Admin Actions'] and (EventID=2521 or EventID=2522)]]
```

#### References

- [Audit administrator events in Microsoft Entra Connect Sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/admin-audit-logging)
- [Collect Microsoft Entra Connect Sync Audit Events](https://medium.com/@verboonalex/collect-microsoft-entra-connect-sync-audit-events-048c8f331e4c)

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
