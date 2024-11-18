# Azure DevOps - Organization Policy - External Guest Access

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098/|
| T1562 | Impair Defenses | https://attack.mitre.org/techniques/T1562/ |

### Description

Block external guest access: Disable the "Allow invitations to be sent to any domain" policy to prevent external guest access if there's no business need for it.

Use the below query to identify when External Guest Access is enabled in Azure DevOps

#### References

- [External Guest access](https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices?view=azure-devops#external-guest-access)
- [Add external users to your organization](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/add-external-user?view=azure-devops)
- [DevOps threat matrix](https://www.microsoft.com/en-us/security/blog/2023/04/06/devops-threat-matrix/)

### Microsoft Sentinel

```kql
AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| extend PolicyName = tostring(Data.PolicyName)
| extend PolicyValue = tostring(Data.PolicyValue)
| where PolicyValue == "OFF"
| where PolicyName == "Policy.DisallowAadGuestUserAccess"
| project TimeGenerated, ActorUPN, IpAddress, PolicyName, PolicyValue, ScopeDisplayName
```
