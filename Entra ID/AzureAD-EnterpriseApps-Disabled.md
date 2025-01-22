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
| where OperationName == "Update service principal"
| extend AppName = tostring(TargetResources[0].displayName)
| extend Enabled = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue))[0])
```

