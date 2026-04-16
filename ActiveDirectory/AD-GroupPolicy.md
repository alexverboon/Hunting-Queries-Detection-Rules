# Active Directory - Group Policy Objects (WORK IN PROGRESS)

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Work in Progress](https://img.shields.io/badge/status-work--in--progress-yellow.svg)

## Query Information

### Description

KQL queries to find Active Directory Group Policy changes

#### References

### Microsoft Defender XDR

Display Active Directory new Group Policy object creations

```kql
IdentityDirectoryEvents
| where ActionType == @"Group Policy was created"
| extend GroupPolicyName = parse_json(AdditionalFields)["GroupPolicyName"]
| extend GroupPolicyId = parse_json(AdditionalFields)["GroupPolicyId"]
| extend DomainName = parse_json(AdditionalFields)["DomainName"]
| project Timestamp, GroupPolicyName, GroupPolicyId, DomainName
```

Display Active Directory Group Policy Object Settings changes

```kql
IdentityDirectoryEvents
| where ActionType == @"Group Policy settings were changed"
| extend GroupPolicyName = parse_json(AdditionalFields)["GroupPolicyName"]
| extend DomainName = parse_json(AdditionalFields)["DomainName"]
| extend GroupPolicyId = parse_json(AdditionalFields)["GroupPolicyId"]
| project Timestamp, GroupPolicyName, GroupPolicyId, DomainName
```

Display Active Directory Group Policy Object Name changes

```kql
IdentityDirectoryEvents
| where ActionType == @"Group Policy Display Name changed"
| extend FROMGroupPolicyDisplayName = parse_json(AdditionalFields)["FROM Group Policy Display Name"]
| extend TOGroupPolicyDisplayName = parse_json(AdditionalFields)["TO Group Policy Display Name"]
| project Timestamp, AccountName, AccountUpn, AccountDisplayName, FROMGroupPolicyDisplayName, TOGroupPolicyDisplayName
```

Display Active Directory Group Policy Object deletions

```kql
IdentityDirectoryEvents
| where ActionType == @"Group policy Deleted changed"
```

```kql
DeviceEvents
| extend ObjectClass = tostring(parse_json(AdditionalFields)["ObjectClass"])
| where ObjectClass == @"groupPolicyContainer"
| extend ObjectDN = tostring(parse_json(AdditionalFields)["ObjectDN"])
```
