# Entra ID - PIM Role Activations

## Query Information

### Description

Use the below query to audit PIM Role Activations

#### References

### Microsoft Sentinel

```kql
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| project TimeGenerated, OperationName, Identity, ResultDescription, TargetResources, CorrelationId
| extend tr = todynamic(TargetResources)
| mv-expand tr
| extend itemType    = tostring(tr.type),
         itemDisplay = tostring(tr.displayName)
| where itemType in ("Role", "Group")
| summarize
        RoleName  = take_anyif(itemDisplay, itemType == "Role"),
        GroupName = take_anyif(itemDisplay, itemType == "Group")
    by TimeGenerated, CorrelationId, ResultDescription, Identity
| project TimeGenerated,Identity, ResultDescription, RoleName, GroupName
```

