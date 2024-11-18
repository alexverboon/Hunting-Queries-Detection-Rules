# Azure DevOps - Organization Policy - Log Audit Events

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.008 | Defense Evasion: Impair Defenses: Disable or Modify Cloud Logs | https://attack.mitre.org/techniques/T1562/008/ |

### Description

Keeping track of activities within your Azure DevOps environment is crucial for security and compliance. Auditing helps you monitor and log these activities, providing transparency and accountability

Use the below query to identify when Log Audit Events is disabled in Azure DevOps

#### References

- [Access, export, and filter audit logs](https://learn.microsoft.com/en-us/azure/devops/organizations/audit/azure-devops-auditing?view=azure-devops&tabs=preview-page)
- [DevOps threat matrix](https://www.microsoft.com/en-us/security/blog/2023/04/06/devops-threat-matrix/)

### Microsoft Sentinel

```kql
AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| extend PolicyName = tostring(Data.PolicyName)
| extend PolicyValue = tostring(Data.PolicyValue)
| where PolicyValue == "OFF"
| where PolicyName == "Policy.LogAuditEvents"
| project TimeGenerated, ActorUPN, IpAddress, PolicyName, PolicyValue, ScopeDisplayName
```
