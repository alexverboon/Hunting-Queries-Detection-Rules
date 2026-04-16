# Defender for Endpoint - DNS

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.003 | Credential Access: Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

### Description

DESCRIPTION

### References

https://github.com/Azure/Azure-Sentinel/blob/master/Detections/ASimWebSession/PossibleDGAContacts.yaml
https://techcommunity.microsoft.com/t5/microsoft-defender-for-identity/default-exclusions-in-suspicious-communication-over-dns-sa/m-p/285348

### Microsoft 365 Defender

```kql
DeviceNetworkEvents
| where ActionType == @"DnsConnectionInspected"
| extend query = parse_json(AdditionalFields).query
| extend rcode_name = parse_json(AdditionalFields).rcode_name
| where rcode_name == 'NXDOMAIN'
```

```kql
let excludeddomains = dynamic(["sophosxl.net","e5.sk","avast.com"]);
DeviceNetworkEvents
| where ActionType == @"DnsConnectionInspected"
| extend query = tostring(parse_json(AdditionalFields).query)
| extend Domain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,tostring(query)))
| extend rcode_name = parse_json(AdditionalFields).rcode_name
| extend qtype_name = tostring(AdditionalFields.qtype_name)
| where qtype_name == 'TXT'
| where Domain !in (excludeddomains)
| project TimeGenerated, DeviceName, query, rcode_name, qtype_name, Domain, AdditionalFields
```

```kql
//https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/DNS%20Essentials/Hunting%20Queries/DomainsWithLargeNumberOfSubDomains.yaml
 DeviceNetworkEvents
| where ActionType == @"DnsConnectionInspected"
| extend query = tostring(parse_json(AdditionalFields).query)
| extend Domain = extract(@"[^.]+\.[^.]+$",0, extract(@"^(?:https?://)?([^/]+)",1,tostring(query)))
| extend rcode_name = parse_json(AdditionalFields).rcode_name
| extend qtype_name = tostring(AdditionalFields.qtype_name)
| extend DomainParts = split(query,'.')
| extend DomainName = strcat(DomainParts[toint(array_length(DomainParts)-2)],'.',DomainParts[toint(array_length(DomainParts)-1)])
| summarize SubDomainCount=dcount(query),make_list(query) by DomainName
```

```kql
//https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/DNS%20Essentials/Hunting%20Queries/PossibleDNSTunnelingOrDataExfiltrationActivity.yaml
  // Setting URI length threshold count, shorter URI's may cause noise, change as needed
  let lookback=1day;
  let uriThreshold = 150;
  let ExcludeDomains=dynamic(["cnr.io", "kr0.io", "arcticwolf.net", "webcfs00.com", "barracudabrts.com", "trendmicro.com", "sophosxl.net", 
  "spotify.com", "e5.sk", "mcafee.com", "opendns.com", "spameatingmonkey.net", "_ldap", "_kerberos", "modsecurity.org", 
  "fdmarc.net", "ipass.com", "wpad"]);
  DeviceNetworkEvents
| where ActionType == @"DnsConnectionInspected"
| extend DnsQuery = tostring(parse_json(AdditionalFields).query)
| extend SrcIpAddr = LocalIP
  | summarize count() by SrcIpAddr, DnsQuery, DeviceName
  | where not(DnsQuery has_any (ExcludeDomains))
  | extend Urilength = strlen(DnsQuery)
  | where Urilength >= uriThreshold
  | order by Urilength
  | extend IP_0_Address = SrcIpAddr
  | extend DNS_0_DomainName = DnsQuery
```

```kql
//https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/DNS%20Essentials/Hunting%20Queries/PotentialBeaconingActivity.yaml
let querystarttime = 2d;
  let queryendtime = 1d;
  let TimeDeltaThreshold = 10;
  let TotalEventsThreshold = 15;
  let PercentBeaconThreshold = 80;
DeviceNetworkEvents
| where ActionType == @"DnsConnectionInspected"
| extend DnsQuery = tostring(parse_json(AdditionalFields).query)
| extend SrcIpAddr = LocalIP
  | where isnotempty(SrcIpAddr)
  | project TimeGenerated, SrcIpAddr, DnsQuery
  | sort by SrcIpAddr asc,TimeGenerated asc
  | serialize
  | extend nextTimeGenerated = next(TimeGenerated, 1), nextSrcIpAddr = next(SrcIpAddr, 1)
  | extend TimeDeltainSeconds = datetime_diff('second',nextTimeGenerated,TimeGenerated)
  | where SrcIpAddr == nextSrcIpAddr
  //Whitelisting criteria/ threshold criteria
  | where TimeDeltainSeconds > TimeDeltaThreshold
  | project TimeGenerated, TimeDeltainSeconds, SrcIpAddr, DnsQuery
  | summarize count(), make_list(TimeDeltainSeconds) by TimeDeltainSeconds, bin(TimeGenerated, 1h), SrcIpAddr, DnsQuery
  | summarize (MostFrequentTimeDeltaCount, MostFrequentTimeDeltainSeconds) = arg_max(count_, TimeDeltainSeconds), TotalEvents=sum(count_)
  by bin(TimeGenerated, 1h), SrcIpAddr, DnsQuery
  | where TotalEvents > TotalEventsThreshold
  | extend BeaconPercent = MostFrequentTimeDeltaCount/toreal(TotalEvents) * 100
  | where BeaconPercent > PercentBeaconThreshold
  | order by BeaconPercent
  | take 50
  | extend IP_0_Address = SrcIpAddr
  | extend DNS_0_DomainName = DnsQuery
```


```kql
// https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/DNS%20Essentials/Hunting%20Queries/UnexpectedTopLevelDomains.yaml
  // Check in last 24hours
  let looback=1d;
  DeviceNetworkEvents
| where ActionType == @"DnsConnectionInspected"
| extend DnsQuery = tostring(parse_json(AdditionalFields).query)
| extend SrcIpAddr = LocalIP
  | summarize Count=count() by SrcIpAddr, DnsQuery
  | extend TopLevelDomain = tostring(split(DnsQuery, ".")[-1])
  | where strlen(TopLevelDomain) > 4
  | order by Count
  | take 25
  | extend IP_0_Address = SrcIpAddr
  | extend DNS_0_DomainName = DnsQuery
```



```
IdentityQueryEvents
| where ActionType == "DNS query"
| extend lenght = strlen(QueryTarget)
| where lenght > 150
| project TimeGenerated, DeviceName, lenght,QueryTarget, QueryType
| summarize count() by QueryTarget
```