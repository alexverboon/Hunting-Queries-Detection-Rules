# Connections to commonly abused top level domains

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1608.005 | Resource Development: Stage Capabilities: Link Target | https://attack.mitre.org/techniques/T1608/005/ |

### Description

Use the below querys to find connections to the commonly aboused domains

#### References

- [Top 10 most abused top level domain (TLD) registries](https://www.spamhaus.org/statistics/tlds/)
- [Google pushes .zip and .mov domains onto the Internet, and the Internet pushes back](https://arstechnica.com/information-technology/2023/05/critics-say-googles-new-zip-and-mov-domains-will-be-a-boon-to-scammers/)

### Defender for Endpoint / Sentinel

Spamhaus - The World's Most Abused TLDs. ***Note*** the list changes monthly visit  [Top 10 most abused top level domain (TLD) registries](https://www.spamhaus.org/statistics/tlds/) to update the list.

```kql
let abusedTLD = dynamic(["rest", "okinawa", "live", "beauty", "bar", "fit", "gq", "cfd", "zone", "top"]);
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend hasIPinRemoteUrl = iif(indexof_regex(RemoteUrl,@"\b(?:\d{1,3}\.){3}\d{1,3}\b") == -1,false, true)
| where hasIPinRemoteUrl==false
| extend TLD = tostring(split(extract(@"\.([a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2})$",0,RemoteUrl,typeof(string)),".")[1])
| where TLD in~ (abusedTLD)
| extend Domain = replace_regex(tostring(extract(@"[^.]+\.[^.]+$",0,RemoteUrl)),"https://","")
| project TimeGenerated, DeviceName,ActionType,RemoteUrl, TLD,Domain, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName
```

ZIP and MOV Domains

```kql
// New Google top level domains
let abusedTLD = dynamic(["zip", "mov"]);
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend hasIPinRemoteUrl = iif(indexof_regex(RemoteUrl,@"\b(?:\d{1,3}\.){3}\d{1,3}\b") == -1,false, true)
| where hasIPinRemoteUrl==false
| extend Domain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,RemoteUrl))
| extend TLD = tostring(split(extract(@"\.([a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2})$",0,Domain,typeof(string)),".")[1])
| where TLD in~ (abusedTLD)
| project TimeGenerated, DeviceName,ActionType,RemoteUrl, TLD,Domain, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName
```

```kql
// URLs in emails
let abusedTLD = dynamic(["rest", "okinawa", "live", "beauty", "bar", "fit", "gq", "cfd", "zone", "top"]);
EmailUrlInfo
| extend Domain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,Url))
| extend TLD = tostring(split(extract(@"\.([a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2})$",0,Domain,typeof(string)),".")[1])
| where TLD in~ (abusedTLD)
| join EmailEvents
on $left. NetworkMessageId == $right.NetworkMessageId
| project TimeGenerated, TLD, Domain, DeliveryAction, SenderFromDomain, ThreatTypes, DetectionMethods,Url
//| where Domain != SenderFromDomain
```

```kql
// URL ClickEvents
let abusedTLD = dynamic(["rest", "okinawa", "live", "beauty", "bar", "fit", "gq", "cfd", "zone", "top","zip","mov","xyz"]);
UrlClickEvents
| extend Domain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,Url))
| extend TLD = tostring(split(extract(@"\.([a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2})$",0,Domain,typeof(string)),".")[1])
| where TLD in~ (abusedTLD)
| project TimeGenerated, TLD, Domain, ActionType, Workload,Url
```
