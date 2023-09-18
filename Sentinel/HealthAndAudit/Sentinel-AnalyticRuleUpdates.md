# Sentinel - Analytic Rules updates

## Query Information

### Description

Use the below querie(s) to retrieve information about Sentinel Analytic Rules updates

#### References

- [Monitor the health and audit the integrity of your analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/monitor-analytics-rule-integrity)


### Microsoft Sentinel

List all analytic rules updates

```kql
SentinelAudit
| where TimeGenerated > ago(180d)
| where Description == "Create or update analytics rule."
| extend CallerIpAddress = tostring(ExtendedProperties.CallerIpAddress)
| extend CallerName = tostring(ExtendedProperties.CallerName)
| extend enabled = tostring(parse_json(tostring(parse_json(tostring(ExtendedProperties.OriginalResourceState)).properties)).enabled)
| project TimeGenerated, SentinelResourceType, SentinelResourceName, CallerIpAddress, CallerName, enabled
```

List all analytic rules updates that were made by users not listed in the CloudAdmins watchlist

```kql
let CloudAdmins = _GetWatchlist('CloudAdmins')
| project ['AccountUPN'];
SentinelAudit
| where TimeGenerated > ago(180d)
| where Description == "Create or update analytics rule."
| extend CallerIpAddress = tostring(ExtendedProperties.CallerIpAddress)
| extend CallerName = tostring(ExtendedProperties.CallerName)
| extend enabled = tostring(parse_json(tostring(parse_json(tostring(ExtendedProperties.OriginalResourceState)).properties)).enabled)
| project TimeGenerated, SentinelResourceType, SentinelResourceName, CallerIpAddress, CallerName, enabled
| where CallerName !in (CloudAdmins)
```

List deleted Analytic Rules

```kql
_SentinelAudit()
| where TimeGenerated > ago(180d)
| where SentinelResourceType =="Analytic Rule"
| where Description =="Analytics rule deleted"
| extend CallerIpAddress = tostring(ExtendedProperties.CallerIpAddress)
| extend CallerName = tostring(ExtendedProperties.CallerName)
| project TimeGenerated, SentinelResourceType, SentinelResourceName, CallerIpAddress, CallerName
```

