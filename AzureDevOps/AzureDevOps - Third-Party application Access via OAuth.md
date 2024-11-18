# Azure DevOps - Organization Policy - Third-Party Access via OAuth

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  |  |  |

### Description

Non-Microsoft application via OAuth: Enable non-Microsoft applications to access resources in your organization through OAuth. This policy is defaulted to off for all new organizations. If you want access to non-Microsoft applications, enable this policy to ensure these apps can access resources in your organization.

Use the below query to identify when Third-Party application access via OAuth is enabled in Azure DevOps

#### References

- [DevOps threat matrix](https://www.microsoft.com/en-us/security/blog/2023/04/06/devops-threat-matrix/)
- [Change application connection & security policies for your organization](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies?view=azure-devops)

### Microsoft Sentinel

```kql
AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| extend PolicyName = tostring(Data.PolicyName)
| extend PolicyValue = tostring(Data.PolicyValue)
| where PolicyValue == "ON"
| where PolicyName == "Policy.DisallowOAuthAuthentication"
| project TimeGenerated, ActorUPN, IpAddress, PolicyName, PolicyValue, ScopeDisplayName
```
