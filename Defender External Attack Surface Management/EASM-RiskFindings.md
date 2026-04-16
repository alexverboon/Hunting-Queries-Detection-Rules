# EASM

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
EasmRisk_CL
|where AssetLastSeen_t > ago(30d)
|where CategoryName_s startswith_cs 'High'
|extend Priority = 'High'
|project-keep Priority,MetricDisplayName_s,SnapshotDateTime_t,AssetName_s
|summarize hint.strategy=shuffle arg_max(SnapshotDateTime_t, *) by Priority,MetricDisplayName_s,AssetName_s
|summarize Count=count() by Priority,MetricDisplayName_s
|order by Count desc 

EasmRisk_CL
|where AssetLastSeen_t > ago(30d)
|where CategoryName_s startswith_cs 'Medium'
|extend Priority = 'Medium'
|project-keep Priority,MetricDisplayName_s,SnapshotDateTime_t,AssetName_s
|summarize hint.strategy=shuffle arg_max(SnapshotDateTime_t, *) by Priority,MetricDisplayName_s,AssetName_s
|summarize Count=count() by Priority,MetricDisplayName_s
|order by Count desc 

EasmRisk_CL
|where AssetLastSeen_t > ago(30d)
|where CategoryName_s startswith_cs 'Low'
|extend Priority = 'Low'
|project-keep Priority,MetricDisplayName_s,SnapshotDateTime_t,AssetName_s
|summarize hint.strategy=shuffle arg_max(SnapshotDateTime_t, *) by Priority,MetricDisplayName_s,AssetName_s
|summarize Count=count() by Priority,MetricDisplayName_s
|order by Count desc 

EasmRisk_CL
|where AssetLastSeen_t > ago(7d)
|extend Priority =  case(CategoryName_s startswith_cs 'High','High',CategoryName_s startswith_cs 'Medium','Medium','Low')
|extend PrioNum = case(Priority == 'High',1,Priority == 'Medium',2,3)
|project-keep AssetName_s,MetricDisplayName_s,AssetLastSeen_t,AssetDescription_s,Priority,PrioNum
|summarize hint.strategy=shuffle arg_max(AssetLastSeen_t, *) by AssetName_s,MetricDisplayName_s,AssetDescription_s,Priority,PrioNum
|project-reorder Priority,AssetName_s
|sort by PrioNum asc
|project-away PrioNum


