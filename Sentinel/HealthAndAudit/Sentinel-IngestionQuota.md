# Sentinel Log Analytics Ingestion Quota Configuration

## Query Information

### Description

Use the below queries to retreive log analytics ingestion quota configuration information and changes

#### References

[Set daily cap on Log Analytics workspace](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/daily-cap)

### Microsoft Sentinel

```kql
arg("").Resources
| where type == "microsoft.operationalinsights/workspaces"
| extend SKUName = tostring(parse_json(tostring(properties.sku)).name)
| extend dailyQuotaGb = tostring(parse_json(tostring(properties.workspaceCapping)).dailyQuotaGb)
| extend quotaNextResetTime = todatetime(tostring(parse_json(tostring(properties.workspaceCapping)).quotaNextResetTime))
| extend retentionInDays = tostring(properties.retentionInDays)
| project name, location, resourceGroup, retentionInDays,SKUName, dailyQuotaGb, quotaNextResetTime
```

Query Quota changes

```kql
let quotaPattern = @"Daily quota changed to (\d+)";
let previousQuotaPattern = @"Previous quota (\d+)";
let changedByPattern = @"Changed by (.+)";
Operation 
| where Detail startswith "Daily quota"
| extend CurrentQuota = extract(quotaPattern,1,Detail)
| extend PreviousQuota = extract(previousQuotaPattern,1,Detail)
| extend ChangedBy = extract(changedByPattern,1,Detail)
```
