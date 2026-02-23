# Defender for Endpoint - AsrVulnerableSignedDriverBlocked - LolDrivers Lookup

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1068 | Exploitation for Privilege Escalation | https://attack.mitre.org/techniques/T1068/ |

### Description

The below query pulls the data from the loldrivers.io dataset and joins it with ***[AsrVulnerableSignedDriverBlocked]***(https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#block-abuse-of-exploited-vulnerable-signed-drivers) events both on SHA1 and SHA256 values since there are some missing SHA1 or SHA256 values in LOLDrivers.

#### References

- [Detecting Vulnerable Drivers (LOLDrivers) the Right Way Using Microsoft Defender for Endpoint](https://academy.bluraven.io/blog/detecting-vulnerable-drivers-using-defender-for-endpoint-kql)
- [Block abuse of exploited vulnerable signed drivers](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#block-abuse-of-exploited-vulnerable-signed-drivers)
- [Strategies to monitor and prevent vulnerable driver attacks](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/strategies-to-monitor-and-prevent-vulnerable-driver-attacks/4103985)

### Author

- **Alex Verboon**

### Credits

- [Mehmet Ergene](https://x.com/Cyb3rMonk) who wrote the original query published [here](https://academy.bluraven.io/blog/detecting-vulnerable-drivers-using-defender-for-endpoint-kql), all I did was replace the Actiontype from ***DriverLoad*** to ***AsrVulnerableSignedDriverBlocked***

## Defender XDR

```kql
let LOLDrivers = externaldata (Category:string, KnownVulnerableSamples:dynamic, Verified:string ) [h@"https://www.loldrivers.io/api/drivers.json"]
    with (format=multijson, ingestionMapping='[{"Column":"Category","Properties":{"Path":"$.Category"}},{"Column":"KnownVulnerableSamples","Properties":{"Path":"$.KnownVulnerableSamples"}},{"Column":"Verified","Properties":{"Path":"$.Verified"}}]')
| mv-expand KnownVulnerableSamples
| extend SHA1 = tostring(KnownVulnerableSamples.SHA1), SHA256 = tostring(KnownVulnerableSamples.SHA256)
;
DeviceEvents
| where ActionType == @"AsrVulnerableSignedDriverBlocked"
| project Timestamp, DeviceName, FileName, SHA256,SHA1, FolderPath
| join kind=inner   (LOLDrivers | where isnotempty(SHA256)) on SHA256
| union (
  DeviceEvents
| where ActionType == @"AsrVulnerableSignedDriverBlocked"
  | join kind=inner (LOLDrivers | where isnotempty(SHA1)) on SHA1
)
```
