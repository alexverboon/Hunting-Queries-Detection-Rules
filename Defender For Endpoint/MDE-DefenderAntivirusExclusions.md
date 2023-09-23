# Defender Antivirus - Exclusions

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |

### Description

Use the below queries to identify Defender Antivirus exclusions modifications

#### References

### Microsoft 365 Defender

Defender Antivirus Exclusions modifications

```kql
DeviceRegistryEvents 
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions' 
```

Defender Antivirus exclusions - Alert

```kql
AlertInfo
| where Title == "Suspicious Microsoft Defender Antivirus exclusion"
| join  AlertEvidence on $left. AlertId ==  $right.AlertId
| project-reorder Timestamp, AlertId, DetectionSource, EntityType, EvidenceRole, FileName, FolderPath, RegistryKey, RegistryValueName, RegistryValueData
```
