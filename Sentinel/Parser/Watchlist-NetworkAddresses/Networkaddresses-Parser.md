# Parser - Networkaddresses Watchlist

## Query Information

### Description

### Preparation

#### References

### Microsoft Sentinel

```kql
// Retrieve Sigin-in logs and show IP Ranges where there's a match
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| evaluate ipv4_lookup(Wl_NetworkAddresses, IPAddress, IPSubnet,return_unmatched = true)
| extend geoinfo =  geo_info_from_ip_address(IPAddress)
| extend country = tostring(geoinfo.country)
| extend city = tostring(geoinfo.city)
| extend state = tostring(geoinfo.state)
| project TimeGenerated, UserPrincipalName, IPAddress, IPSubnet, RangeName, Tags, WatchlistSource, country, state, city
```

```kql
// Only retrieve Sigin-in logs from known IP ranges (return_unmatched = false)
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| evaluate ipv4_lookup(Wl_NetworkAddresses, IPAddress, IPSubnet,return_unmatched = false)
| extend geoinfo =  geo_info_from_ip_address(IPAddress)
| extend country = tostring(geoinfo.country)
| extend city = tostring(geoinfo.city)
| extend state = tostring(geoinfo.state)
| project TimeGenerated, UserPrincipalName, IPAddress, IPSubnet, RangeName, Tags, WatchlistSource,country, state, city
```

```kql
// Retrieve Sign-in logs from unknown IPRanges
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| evaluate ipv4_lookup(Wl_NetworkAddresses, IPAddress, IPSubnet,return_unmatched = true)
| where isempty(IPSubnet)
| extend geoinfo =  geo_info_from_ip_address(IPAddress)
| extend country = tostring(geoinfo.country)
| extend city = tostring(geoinfo.city)
| extend state = tostring(geoinfo.state)
| project TimeGenerated, UserPrincipalName, IPAddress, Type, Category, country, state, city
```

```kql
// Retrieve Sign-in logs from unknown IPRanges and summarize location
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| evaluate ipv4_lookup(Wl_NetworkAddresses, IPAddress, IPSubnet,return_unmatched = true)
| where isempty(IPSubnet)
| extend geoinfo =  geo_info_from_ip_address(IPAddress)
| extend country = tostring(geoinfo.country)
| extend city = tostring(geoinfo.city)
| extend state = tostring(geoinfo.state)
| project TimeGenerated, UserPrincipalName, IPAddress, Type, Category, country, state, city
| summarize TotalUsers = dcount(UserPrincipalName), Users = make_set(UserPrincipalName) by country,city, IPAddress
```
