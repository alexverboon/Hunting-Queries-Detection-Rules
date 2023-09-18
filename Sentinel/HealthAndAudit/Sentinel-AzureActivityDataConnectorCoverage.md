# Sentinel - Azure Activity Connector - log collection coverage

## Query Information

### Description

Use the below query to Identify Azure Subscriptions that are not monitored by the Azure Activity Data Connector in Sentinel

#### References

- [Azure Activity connector for Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/azure-activity)
- [Moving Azure Activity Connector to an improved method](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/moving-azure-activity-connector-to-an-improved-method/ba-p/2479552)

### Microsoft Sentinel

```kql
// Identify Azure Subscriptions that are not monitored by the Azure Activity Data Connector in Sentinel
let allsubscriptions = 
arg("").resourcecontainers
| where type == "microsoft.resources/subscriptions"
| distinct subscriptionId, name;
allsubscriptions
| join kind=leftouter  (AzureActivity
| extend AzureActivitySyubscriptionId = SubscriptionId
| distinct AzureActivitySyubscriptionId)
on $left. subscriptionId == $right.AzureActivitySyubscriptionId
| extend IsMonitored = iff(isempty(AzureActivitySyubscriptionId),"No","Yes")
| project subscriptionId, name, AzureActivitySyubscriptionId, IsMonitored
```

