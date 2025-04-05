# Defender for Office 365 - Blocked URLs

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                      | Link                                                         |
| ---          | ---                        | ---                                                          |
| T1566        | Phishing                   | [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/) |
| T1566.002    | Spearphishing Link         | [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/) |

### Description

Use the below querys to find the domains of URLs that were blocked

### Defender XDR

```kql
UrlClickEvents
| where TimeGenerated > ago(90d)
| where ActionType == "ClickBlocked"
| where DetectionMethods has_any ("URL")
| extend Domain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,Url))
| extend TLD = tostring(split(extract(@"\.([a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2})$",0,Domain,typeof(string)),".")[1])
| project TimeGenerated, TLD, Domain,IPAddress, ThreatTypes,DetectionMethods, IsClickedThrough,Url
```

```kql
EmailEvents
| where DeliveryAction == "Blocked"
| where DetectionMethods has_any ("URL","domain")
| join EmailUrlInfo
on $left.NetworkMessageId == $right.NetworkMessageId
| extend Domain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,Url))
| extend TLD = tostring(split(extract(@"\.([a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2})$",0,Domain,typeof(string)),".")[1])
| project TimeGenerated,TLD, Domain, ThreatTypes, ThreatNames, DetectionMethods, SenderFromDomain, Url
```
