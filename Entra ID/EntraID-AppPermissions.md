# TITLE

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.003 | Credential Access: Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

### Description

DESCRIPTION


#### References



### Microsoft 365 Defender




```kql
AuditLogs
| where ActivityDisplayName == "Add app role assignment to service principal"
| mv-expand parse_json(TargetResources)
| extend Prop = parse_json(TargetResources.modifiedProperties)
| mv-expand Prop
| where Prop.displayName == "AppRole.Value"
| extend Value = parse_json(tostring(Prop.newValue)) 
```

