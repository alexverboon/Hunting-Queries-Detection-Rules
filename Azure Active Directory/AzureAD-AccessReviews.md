# Entra ID - Access Review Activities

## Query Information

### Description

Use the below queries to retrieve Entra ID Access Review activities

#### References

- [What are access reviews?](https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview)

### Microsoft Sentinel

Deny decisions

```kql
AuditLogs
| where Category == "Policy"
| where OperationName == "Deny decision"
| extend AccessReview = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TargetUser = tostring(TargetResources[2].userPrincipalName)
```

Approval decisions

```kql
AuditLogs
| where Category == "Policy"
| where OperationName == "Approve decision"
| extend AccessReview = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TargetUser = tostring(TargetResources[2].userPrincipalName)
```

Bulk approval

```kql
AuditLogs
| where Category == "Policy"
| where OperationName == "Bulk Approve decisions"
| extend AccessReview = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)

```

Delete Access Review

```kql
AuditLogs
| where Category == "Policy"
| where OperationName == "Delete access review"
| extend AccessReviewName = tostring(TargetResources[0].displayName)
| extend IPAddress = tostring(AdditionalDetails[3].value)
| project TimeGenerated, AccessReviewName, OperationName, IPAddress
```

Create Access Review

```kql
AuditLogs
| where Category == "Policy"
| where OperationName == "Create access review"
| extend AccessReviewName = tostring(TargetResources[1].displayName)
| extend IPAddress = tostring(AdditionalDetails[3].value)
| project TimeGenerated, AccessReviewName, OperationName, IPAddress
```kql