# Exposure Management - A potentially malicious URL click was detected

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 ] | Initial Access: https://attack.mitre.org/techniques/T1566/002/ | https://attack.mitre.org/techniques/T1566/002/ |


### Description

Custom DefenderXDR detection rule for critical identities marked by exposure management clicking on malicious email link. This would triggered the isolation of the user account and devices impacted to minimize lateral movement.

#### References


### Credits
 - Author of the query is: [Steven Lim](https://www.linkedin.com/in/0x534c/) share via LinkedIn post.


### Microsoft Defender XDR

```kql
let CriticalIdentities =
ExposureGraphNodes
| where set_has_element(Categories, "identity")
| where isnotnull(NodeProperties.rawData.criticalityLevel) and NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| extend AccountUPN = tostring(NodeProperties.rawData.accountUpn)
| distinct AccountUPN;
AlertInfo
| where Title == "A potentially malicious URL click was detected"
| join AlertEvidence on AlertId
| join EmailEvents on NetworkMessageId
| where RecipientEmailAddress has_any (CriticalIdentities)
```

