# Sentinel - Email sending limit exceeded

## Query Information

### Description

Use the below query to review 'Email sending limit exceeded' incidents.

#### References

### Microsoft Sentinel

```kql
let lookBack = 7d;
let IncTitle = "Email sending limit exceeded";
SecurityIncident
| where TimeGenerated > ago(lookBack)
| where Title == IncTitle
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| join  (SecurityAlert)
on $left. AlertId == $right. SystemAlertId
| mv-expand parse_json(Entities)
| extend EType = tostring((Entities.Type))
| where EType == "mailbox"
| extend MailboxPrimaryAddress = tostring(Entities.MailboxPrimaryAddress)
| extend DisplayName = tostring(Entities.DisplayName)
```
