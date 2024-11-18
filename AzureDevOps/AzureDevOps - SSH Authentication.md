# Azure DevOps - Organization Policy - SSH Authentication

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1133 | Initial Access: Brute Force: External Remote Services | https://attack.mitre.org/techniques/T1133/ |

### Description

The Azure DevOps SSH Authentication setting allows you to enable applications to connect to your organization's Git repos through SSH.

Use the below query to identify when SSH Authentication is enabled in Azure DevOps

#### References

- [Azure DevOps - Use SSH key authentication](https://learn.microsoft.com/en-us/azure/devops/repos/git/use-ssh-keys-to-authenticate?view=azure-devops)
- [DevOps threat matrix](https://www.microsoft.com/en-us/security/blog/2023/04/06/devops-threat-matrix/)
- [Change application connection & security policies for your organization](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies?view=azure-devops)

### Microsoft Sentinel

```kql
AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| extend PolicyName = tostring(Data.PolicyName)
| extend PolicyValue = tostring(Data.PolicyValue)
| where PolicyName == "Policy.DisallowSecureShell"
| where PolicyValue == "ON"
| project TimeGenerated, ActorUPN, IpAddress, PolicyName, PolicyValue, ScopeDisplayName
```

