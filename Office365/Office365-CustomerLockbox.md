# Office 365 - Customer Lockbox activities in Exchange Online, SharePoint, OneDrive, Teams and Windows 365

## Query Information

### Description

The below query will show customer lockbox request related events in Exchange Online, SharePoint, OneDrive, Teams and Windows 365

| Audit record property | Description |
| ----------------------| ------------|
| Date | The date and time when the Customer Lockbox request was approved or denied.|
| IP address | The IP address of the machine the approver used to approve or deny a request.|
| User | The service account BOXServiceAccount@[customerforest].prod.outlook.com. |
| Activity | Set-AccessToCustomerDataRequest; this is the auditing activity that is logged when you approve or deny a Customer Lockbox request.|
| Item | The Guid of the Customer Lockbox request |

#### References

- [Microsoft Purview Customer Lockbox](https://learn.microsoft.com/en-us/purview/customer-lockbox-requests)

### Microsoft 365 Defender / Microsoft Sentinel

```kql
OfficeActivity
| where Operation contains 'Set-AccessToCustomerDataRequest'
| extend UserKey startswith  'BOXServiceAccount@'
| extend RequestID = tostring(parse_json(Parameters)[2].Value)
| extend ApprovalDecision = tostring(parse_json(Parameters)[1].Value)
| project TimeGenerated,ClientIP,UserKey,ExternalAccess,Operation, RequestID,ApprovalDecision
```
