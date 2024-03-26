# Microsoft Security Exposure Management - Storage Accounts

## Query Information

### Description

Use the below queries to retrieve Azure Storage Accounts from the enterprise exposure graph.

#### References

- [Introducing Microsoft Security Exposure Management](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/introducing-microsoft-security-exposure-management/ba-p/4080907)
- [Query the enterprise exposure graph](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph)

### Microsoft Defender XDR

Retrieve Azure - Storage Accounts data

```kql
ExposureGraphNodes
| where NodeLabel == @"microsoft.storage/storageaccounts"
| extend StorageAccountName = NodeName
| extend Properties = parse_json(NodeProperties.rawData)
| extend Environment = parse_json(Properties).environmentName
| extend EnvironmentRegionName = parse_json(Properties).nativeEnvironmentRegionName
| extend InputString = tostring(parse_json((EntityIds)[0].id))
| parse InputString with "/subscriptions/" subscriptionId "/resourcegroups" * 
| parse InputString with "/subscriptions/" * "/resourcegroups/" resourceGroup "/providers" *
| project StorageAccountName, Environment, EnvironmentRegionName, subscriptionId, resourceGroup
```


