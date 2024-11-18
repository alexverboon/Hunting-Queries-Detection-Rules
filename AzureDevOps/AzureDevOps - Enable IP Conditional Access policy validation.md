# Azure DevOps - Organization Policy - Enable IP Conditional Access Policy Validation

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1556.009 | Modify Authentication Process: Conditional Access Policies | https://attack.mitre.org/techniques/T1556/009/ |

### Description

When you sign in to the web portal of a Microsoft Entra ID-backed organization, Microsoft Entra ID always performs validation for any Conditional Access Policies (CAPs) set by tenant administrators.

Azure DevOps can also perform more CAP validation once you're signed in and navigating through a Microsoft Entra ID-backed organization:

If the “Enable IP Conditional Access policy Validation” organization policy is enabled, we check IP fencing policies on both web and non-interactive flows, such as non-Microsoft client flows like using a PAT with git operations.
Sign-in policies might be enforced for PATs as well. Using PATs to make Microsoft Entra ID calls requires adherence to any sign-in policies that are set. For example, if a sign-in policy requires that a user sign in every seven days, you must also sign in every seven days to continue using PATs for Microsoft Entra ID requests.
If you don't want any CAPs to be applied to Azure DevOps, remove Azure DevOps as a resource for the CAP. We don't enforce CAPs on Azure DevOps on an organization-by-organization basis.

Use the below query to identify when IP Conditional Access Policy Validation disabled in Azure DevOps

#### References

- [Change application connection & security policies for your organization](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies?view=azure-devops)
- [DevOps threat matrix](https://www.microsoft.com/en-us/security/blog/2023/04/06/devops-threat-matrix/)
- [Microsoft Azure Security Control Mappings to MITRE ATT&CK®](https://center-for-threat-informed-defense.github.io/security-stack-mappings/Azure/README.html)

### Microsoft Sentinel

```kql
AzureDevOpsAuditing
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| extend PolicyName = tostring(Data.PolicyName)
| extend PolicyValue = tostring(Data.PolicyValue)
| where PolicyValue == "OFF"
| where PolicyName == "Policy.EnforceAADConditionalAccess"
| project TimeGenerated, ActorUPN, IpAddress, PolicyName, PolicyValue, ScopeDisplayName
```
