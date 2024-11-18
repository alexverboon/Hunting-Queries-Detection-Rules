# Azure DevOps - Organization Policy - Additional Protection when using public package registries

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  |  |  |

### Description

Use the below query to identify when Additional Protection when using public package registries is disabled in Azure DevOps

#### References

- [Changes to Azure Artifacts Upstream Behavior](https://devblogs.microsoft.com/devops/changes-to-azure-artifact-upstream-behavior/)

### Microsoft Sentinel

```kql
AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| extend PolicyName = tostring(Data.PolicyName)
| extend PolicyValue = tostring(Data.PolicyValue)
| where PolicyValue == "OFF"
| where PolicyName == "Policy.ArtifactsExternalPackageProtectionToken"
| project TimeGenerated, ActorUPN, IpAddress, PolicyName, PolicyValue, ScopeDisplayName
```
