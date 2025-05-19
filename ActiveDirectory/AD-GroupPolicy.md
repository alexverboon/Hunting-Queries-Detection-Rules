# Active Directory - Group Policy Objects (WORK IN PROGRESS)

## Query Information

### Description

KQL queries to find Active Directory Group Policy changes

#### References

### Microsoft Defender XDR

```kql
IdentityDirectoryEvents
| where ActionType == @"Group Policy was created"
| extend GroupPolicyName = tostring(parse_json(AdditionalFields).GroupPolicyName)
```

```kql
IdentityDirectoryEvents
| where ActionType == @"Group Policy settings were changed"
```

```kql
DeviceEvents
| where ActionType == @"DirectoryServiceObjectCreated"
| where parse_json(AdditionalFields)["ObjectClass"] == 'groupPolicyContainer'
```

```kql
IdentityDirectoryEvents
| where ActionType == @"Group Policy settings were changed"
```

```kql
IdentityDirectoryEvents
| where ActionType == @"Group Policy Display Name changed"
```

