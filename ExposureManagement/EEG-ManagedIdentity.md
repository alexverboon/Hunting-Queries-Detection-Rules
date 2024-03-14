# Microsoft Security Exposure Management - Managed Identity

## Query Information

### Description

Use the below queries to retrieve Entra ID managed Identity from the enterprise exposure graph.

#### References

- [Introducing Microsoft Security Exposure Management](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/introducing-microsoft-security-exposure-management/ba-p/4080907)
- [Query the enterprise exposure graph](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph)

### Microsoft Defender XDR

Retrieve Entra ID - Managed Identity data

```kql
ExposureGraphNodes 
| where NodeLabel == @"managedidentity"
| extend Type = tostring(type = parse_json(NodeProperties).rawData.managedIdentityMetadata.type)
| extend name = tostring(parse_json(NodeProperties).rawData.identityMetadata.data.name)
| extend accountType = tostring(parse_json(NodeProperties).rawData.managedIdentityMetadata.data.accountType)
| extend AadObjectId = NodeName
| extend attachedResourceId = parse_json(NodeProperties).rawData.managedIdentityMetadata.data.attachedResourceId
| project Type, name, accountType, attachedResourceId, AadObjectId

```


