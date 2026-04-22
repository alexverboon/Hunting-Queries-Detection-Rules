# Defender for Identity - Active Directory - Password Policy Change

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1484 | Domain Policy Modification | https://attack.mitre.org/techniques/T1484/ |
| 1484.001 | Group Policy Modification | https://attack.mitre.org/techniques/T1484/001/ |

### Description

The below query retrieves events from Defender for Identity when Active Directory Domain Account Password policies are changed.

#### References

- [Password Policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/password-policy)

### Author

- **Alex Verboon**

## Defender XDR

```kql
IdentityDirectoryEvents
| where ActionType == @"Group Policy settings were changed"
| extend Info = parse_json(AdditionalFields)
| extend MachinePolicies = tostring(Info.MachinePolicies),
         GroupPolicyName = tostring(Info.GroupPolicyName),
         GroupPolicyId   = tostring(Info.GroupPolicyId),
         DomainName      = tostring(Info.DomainName),
         Category        = tostring(Info.Category),
         AttackTechniques = tostring(Info.AttackTechniques)
| project TimeGenerated, DomainName, GroupPolicyName, GroupPolicyId, MachinePolicies, Category, AttackTechniques
| mv-expand PolicyEntry = split(MachinePolicies, ",") to typeof(string)
| extend FullPath    = tostring(split(PolicyEntry, "=")[0]),
         PolicyValue = tostring(split(PolicyEntry, "=")[1])
| extend PathParts   = split(FullPath, @"\"),
         PolicyName  = tostring(split(FullPath, @"\")[-1])
| extend PolicyPath  = strcat_array(array_slice(PathParts, 0, array_length(PathParts) - 2), @"\")
| where PolicyPath == @"Account Policies\PasswordPolicy"
| summarize Settings = make_bag(pack(PolicyName, PolicyValue)) 
    by TimeGenerated, GroupPolicyId, GroupPolicyName, DomainName, AttackTechniques, Category, PolicyPath
```


