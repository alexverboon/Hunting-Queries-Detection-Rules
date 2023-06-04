# NTFS File Attributes - alternate data streams

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1564.004 | Defemse Evasion:Hide Artifacts: NTFS File Attributes | https://attack.mitre.org/techniques/T1564/004/ |

### Description

Use the below queries to identify alternate data streams


#### References

- [Sneaky Tip and Tricks with Alternate Data Streams](https://www.sans.org/presentations/sneaky-tip-and-tricks-with-alternate-data-streams/)
- [Malicious and Steganographic Potential in NTFS Alternate Data Streams](https://www.giac.org/paper/gsec/3075/malicious-steganographic-potential-ntfs-alternate-data-streams/105112)



### Microsoft 365 Defender


```kql
DeviceAlertEvents
| where Title contains "Process execution from an alternate data stream (ADS)"
```

```kql
DeviceProcessEvents
| where FileName   contains ":"
// | invoke FileProfile(SHA256,100) 
```


