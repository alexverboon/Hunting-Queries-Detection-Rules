# Azure Resource Graph

## Query Information

### Description

Use the below queries to query data in Azure Resource Graph

#### References

- [Query Azure Resource Graph from Azure Monitor](https://techcommunity.microsoft.com/t5/azure-observability-blog/query-azure-resource-graph-from-azure-monitor/ba-p/3918298)
- [Query data in Azure Data Explorer and Azure Resource Graph from Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/azure-monitor-data-explorer-proxy)
- [Azure Resource Graph table and resource type reference](https://learn.microsoft.com/en-us/azure/governance/resource-graph/reference/supported-tables-resources)

### Microsoft Sentinel

#### Resources

List all Resource types

```kql
arg("").Resources
| distinct type
```

List all 'Sentinel' workbooks

```kql
arg("").Resources
| where type == "microsoft.insights/workbooks"
| extend category = tostring(properties.category)
| extend displayName = tostring(properties.displayName)
| where category == "sentinel"
| project displayName, resourceGroup
```

List Virtual Machines

```kql
arg("").Resources
| where type == "microsoft.compute/virtualmachines"
| extend vmSize = tostring(parse_json(tostring(properties.hardwareProfile)).vmSize)
| extend computerName = tostring(parse_json(tostring(properties.osProfile)).computerName)
| project name, computerName, location, resourceGroup,vmSize
```

List Log Analytics Workspace information

```kql
arg("").Resources
| where type == "microsoft.operationalinsights/workspaces"
| extend SKUName = tostring(parse_json(tostring(properties.sku)).name)
| extend dailyQuotaGb = tostring(parse_json(tostring(properties.workspaceCapping)).dailyQuotaGb)
| extend quotaNextResetTime = todatetime(tostring(parse_json(tostring(properties.workspaceCapping)).quotaNextResetTime))
| extend retentionInDays = tostring(properties.retentionInDays)
| project name, location, resourceGroup, retentionInDays,SKUName, dailyQuotaGb, quotaNextResetTime
```

List user assigned identities

```kql
arg("").Resources
| where type == "microsoft.managedidentity/userassignedidentities"
| extend clientId = tostring(properties.clientId)
| extend principalId = tostring(properties.principalId)
| project name, resourceGroup, clientId, principalId
```

List Logic App (Playbook) resources

```kql
arg("").Resources
| where type == "microsoft.logic/workflows"
| extend IdentityType = tostring(identity.type)
| extend createdTime = todatetime(tostring(properties.createdTime))
| extend changedTime = todatetime( tostring(properties.changedTime))
| extend state = tostring(properties.state)
| project name, state, location,resourceGroup, IdentityType, createdTime, changedTime
```

List API connections

```kql
arg("").Resources
| where type == "microsoft.web/connections"
| extend connectionState = tostring(properties.connectionState)
| extend token_clientId = tostring(parse_json(tostring(properties.parameterValues)).["token:clientId"])
| extend ConnectionDisplayName = tostring(parse_json(tostring(properties.api)).displayName)
| extend AuthUser = tostring(parse_json(tostring(properties.authenticatedUser)).name)
| project name, type, resourceGroup, connectionState, ConnectionDisplayName, AuthUser, token_clientId
```

List Query Packs

```kql
arg("").Resources
| where type == "microsoft.operationalinsights/querypacks"
| project name, resourceGroup
```

#### Azure Policy Resources

List all Azure Policy types

```kql
arg("").policyresources
| distinct type
```

#### Azure Security Resources

```kql
arg("").securityresources
| distinct type
```

#### Azure Resource Health

List active resource health alerts

```kql
arg("").servicehealthresources
| extend EventSource = tostring(properties.EventSource)
| extend Status = tostring(parse_json(tostring(parse_json(tostring(properties.Impact))[0].ImpactedRegions))[0].Status)
| extend Title = tostring(properties.Title)
| extend TrackingId = tostring(properties.TrackingId)
| extend ImpactStartTime_ = todatetime(tostring(properties.ImpactStartTime))
| extend LastUpdateTime = todatetime(tostring(properties.LastUpdateTime))
| where Status == "Active"
```

#### IOT Security Resources

```kql
arg("").iotsecurityresources
| distinct type
```

List IOT Devices

```kql
arg("").iotsecurityresources
| where type == "microsoft.iotsecurity/locations/devicegroups/devices"
| extend deviceCategoryDisplayName = tostring(properties.deviceCategoryDisplayName)
| extend deviceDataSource = tostring(properties.deviceDataSource)
| extend deviceName = tostring(properties.deviceName)
| extend deviceSubTypeDisplayName = tostring(properties.deviceSubTypeDisplayName)
```

#### authorizationresources

list Roles

```kql
arg("").authorizationresources
| where type == "microsoft.authorization/roledefinitions"
| extend description = tostring(properties.description)
| extend roleName = tostring(properties.roleName)
| extend roletype = tostring(properties.type)

```

#### Management Groups, Subscriptions

```kql
arg("").resourcecontainers
| where type == "microsoft.resources/subscriptions"
```
