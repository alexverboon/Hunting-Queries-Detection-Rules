# Defender for Cloud - CloudAuditEvents

## Query Information

### Description

The ***CloudAuditEvents*** table in the advanced hunting schema contains information about cloud audit events for various cloud platforms protected by the organization's Microsoft Defender for Cloud.


#### References

- [CloudAuditEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudauditevents-table)


### Microsoft Defender XDR

To get a sample list of VM creation commands performed in the last seven days:

```kql
CloudAuditEvents
| where Timestamp > ago(7d)
| where OperationName startswith "Microsoft.Compute/virtualMachines/write"
| extend Status = RawEventData["status"], SubStatus = RawEventData["subStatus"]
| sample 10
```



