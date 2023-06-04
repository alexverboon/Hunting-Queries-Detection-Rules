# Azure Active Directory - Suspicious Resource deployment

## Query Information

### Description

The Sentinel Analytics Rule *Suspicious Resource deployment* Identifies Identifies when a rare Resource and ResourceGroup deployment occurs by a previously unseen caller.

#### References

### Microsoft Sentinel

Use the below query to get a summary of these alerts and the total # of entities

```kql
let ioc_lookBack = 90d;
let IncTitle = "Suspicious Resource deployment";
SecurityIncident
| where TimeGenerated > ago(90d)
| where Title == IncTitle
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| join  (SecurityAlert)
on $left. AlertId == $right. SystemAlertId
| mv-expand parse_json(Entities)
| extend EType = tostring((Entities.Type))
| project TimeGenerated, IncidentNumber, EType, IncidentUrl
| evaluate pivot(EType)
```
