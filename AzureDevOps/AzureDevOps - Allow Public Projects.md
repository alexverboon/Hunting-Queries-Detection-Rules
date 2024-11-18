# Azure DevOps - Organization Policy - Allow Public Projects

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1213.003 | Data from Information Repositories: Code Repositories | https://attack.mitre.org/techniques/T1213/003/ |

### Description

Disable “Allow public projects”: In your organization’s policy settings, disable the option to create public projects. Switch project visibility from public to private as needed. Users who haven’t signed in have read-only access to public projects, while signed-in users can be granted access to private projects and make permitted changes.

Organization’s public repositories – Access to the organization’s public repositories that are configured with CI/CD capabilities. Depending on the organization’s configuration, these repositories may have the ability to trigger a pipeline run after a pull request (PR) is created.

Use the below query to identify when Allow Public Projects is enabled in Azure DevOps

#### References

- [Azure DevOps Project Level Permissions](https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices?view=azure-devops#project-level-permissions)
- [Change project visibility to public or private](https://learn.microsoft.com/en-us/azure/devops/organizations/projects/make-project-public?view=azure-devops)
- [DevOps threat matrix](https://www.microsoft.com/en-us/security/blog/2023/04/06/devops-threat-matrix/)

### Microsoft Sentinel

```kql
AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| extend PolicyName = tostring(Data.PolicyName)
| extend PolicyValue = tostring(Data.PolicyValue)
| where PolicyValue == "ON"
| where PolicyName == "Policy.AllowAnonymousAccess"
| project TimeGenerated, ActorUPN, IpAddress, PolicyName, PolicyValue, ScopeDisplayName
```
