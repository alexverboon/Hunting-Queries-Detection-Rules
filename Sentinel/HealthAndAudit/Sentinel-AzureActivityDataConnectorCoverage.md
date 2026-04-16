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
| extend AzureActivitySubscriptionId = SubscriptionId
| distinct AzureActivitySubscriptionId)
on $left. subscriptionId == $right.AzureActivitySubscriptionId
| extend IsMonitored = iff(isempty(AzureActivitySubscriptionId),"No","Yes")
| project subscriptionId, name, AzureActivitySubscriptionId, IsMonitored
```

### Azure Resource Graph

```kql
policyResources
| where type == "microsoft.authorization/policyassignments"
| project name, id, type, properties.displayName, properties.scope, properties.policyDefinitionId, properties.enforcementMode
| where properties_displayName == 'Configure Azure Activity logs to stream to specified Log Analytics workspace'
| project name, properties_displayName, properties_scope
```



AzureActivity
    | extend SubscriptionId = tostring(SubscriptionId)
    | distinct SubscriptionId
| join (ExposureGraphNodes
    | where NodeLabel == "subscriptions"
    | extend Parsed = parse_json(NodeProperties)
    | extend
        SubscriptionId = tostring(Parsed.rawData.hierarchyIdentifier),
        SubscriptionName = tostring(Parsed.rawData.subscriptionName),
        EnvironmentName = tostring(Parsed.rawData.environmentName)
    | project EnvironmentName, SubscriptionId, SubscriptionName) on SubscriptionId
| extend IsMonitored = iff(isempty(SubscriptionId1), "No", "Yes")
| project SubscriptionId, SubscriptionName, EnvironmentName, IsMonitored
| order by SubscriptionName asc