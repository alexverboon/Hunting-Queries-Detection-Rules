# High-Privilege Identities Across Subscriptions

## Query Information

### Description

This query finds identities with elevated roles like Owner or Contributor, helping you assess potential privilege escalation risks.


#### References

- [Performing Advanced Risk Hunting in Defender for Cloud](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/performing-advanced-risk-hunting-in-defender-for-cloud/4420633)


### Author

- **Microsoft**

## Defender XDR

```kql
ExposureGraphEdges
| where EdgeLabel == "has permissions to"
| extend Roles = parse_json(EdgeProperties).rawData.permissions.roles
| mv-expand Roles
| where Roles.name in ("Owner", "Contributor")
| join kind=inner (
    ExposureGraphNodes
    | project NodeId, Department = tostring(NodeProperties.department)
) on $left.SourceNodeId == $right.NodeId
```
