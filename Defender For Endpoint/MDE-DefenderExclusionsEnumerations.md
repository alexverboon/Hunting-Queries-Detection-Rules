# MDE - Defender Antivirus Exclusion Enumeration

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1564.012 | Defense Evasion: Hide Artifacts: File/Path Exclusions | https://attack.mitre.org/techniques/T1564/012/ |

### Description

Use the below query to identify Defender Antivirus Exclusion Path enumeration activities that use the mpcmdrun.exe

#### References

- [Peeking Behind the Curtain: Finding Defender’s Exclusions](https://blog.fndsec.net/2024/10/04/uncovering-exclusion-paths-in-microsoft-defender-a-security-research-insight/)
- [Hide Artifacts: File/Path Exclusions](https://attack.mitre.org/techniques/T1564/012/)

### Microsoft Sentinel

```kql
let arguments = dynamic(['ScanType 3 -File',"-CheckExclusion"]);
DeviceProcessEvents
| where FileName == "MpCmdRun.exe"
| where ProcessCommandLine has_any (arguments)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| summarize Count = count(), Commands = make_set(ProcessCommandLine) by bin(TimeGenerated,1m), DeviceName
// exclude threshold or tune as per your needs
// | where Count > 1
```
