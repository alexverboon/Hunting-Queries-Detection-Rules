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
EasmAsset_CL
| where TimeGenerated > ago(30d)
| where AssetType_s contains "IP_Address"
| distinct AssetName_s

EasmAsset_CL
| where TimeGenerated > ago(30d)
| where AssetType_s == "DOMAIN"
| distinct AssetName_s

EasmAsset_CL
| where TimeGenerated > ago(30d)
| where AssetType_s == "HOST"
| distinct AssetName_s
```

