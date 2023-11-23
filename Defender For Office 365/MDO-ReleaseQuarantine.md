# Microsoft Defender for Office 365 - Release from Quarantine

## Query Information


### Description

Use the below query to list all e-mail messages that were released from quarantine


#### References

- [Manage quarantined messages and files as a user](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/quarantine-end-user?view=o365-worldwide)
- [Manage quarantined messages and files as an admin](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/quarantine-admin-manage-messages-files?view=o365-worldwide)

### Microsoft Sentinel


List all e-mail messages that were released from quarantine in Microsoft Exchange Online

```kql
EmailPostDeliveryEvents
| where TimeGenerated > ago(7d)
| where Action == "Quarantine release"
| project TimeGenerated, Action, ActionTrigger, ActionType, DeliveryLocation, RecipientEmailAddress, NetworkMessageId
| join EmailEvents
on $left. NetworkMessageId == $right. NetworkMessageId
| project TimeGenerated, Action, ActionTrigger, ActionType, Subject, RecipientEmailAddress, SenderFromAddress, SenderFromDomain
//| summarize count() by SenderFromDomain
```

