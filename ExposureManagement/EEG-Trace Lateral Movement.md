# Trace Lateral Movement

## Query Information

### Description

This multi-hop query simulates an attacker moving from one compromised resource to another

#### References

- [Performing Advanced Risk Hunting in Defender for Cloud](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/performing-advanced-risk-hunting-in-defender-for-cloud/4420633)

### Author

- **Microsoft**

## Defender XDR

```kql
// Step 1: Identify High-Risk Azure VMs with High-Severity Vulnerabilities
let HighRiskVMs =
    ExposureGraphNodes
    | where NodeLabel == "microsoft.compute/virtualmachines"
    | extend NodeProps = parse_json(NodeProperties)
    | extend RawData = parse_json(tostring(NodeProps.rawData))  // Parse rawData as JSON
    | extend VulnerabilitiesData = parse_json(tostring(RawData.hasHighSeverityVulnerabilities))  // Extract nested JSON
    | where toint(VulnerabilitiesData.data['count']) > 0  // Filter VMs with count > 0
    | project VMId = NodeId, VMName = NodeName, VulnerabilityCount = VulnerabilitiesData.data['count'], NodeProperties;
// Step 2: Identify Critical Storage Accounts with Sensitive Data
let CriticalStorageAccounts =
    ExposureGraphNodes
    | where NodeLabel == "microsoft.storage/storageaccounts"
    | extend NodeProps = parse_json(NodeProperties)
    | extend RawData = parse_json(tostring(NodeProps.rawData))  // Parse rawData as JSON
    | where RawData.containsSensitiveData == "true"  // Check for sensitive data
    | project StorageAccountId = NodeId, StorageAccountName = NodeName;
// Step 3: Find Lateral Movement Paths from High-Risk VMs to Critical Storage Accounts
let LateralMovementPaths =
    ExposureGraphEdges
    | where EdgeLabel in ("has role on", "has permissions to", "can authenticate to")  // Paths that allow access
    | project SourceNodeId, SourceNodeName, SourceNodeLabel, TargetNodeId, TargetNodeName, EdgeLabel;
// Step 4: Correlate High-Risk VMs with Storage Accounts They Can Access
HighRiskVMs
| join kind=inner LateralMovementPaths on $left.VMId == $right.SourceNodeId
| join kind=inner CriticalStorageAccounts on $left.TargetNodeId == $right.StorageAccountId
| project VMName, StorageAccountName = TargetNodeName, EdgeLabel, VulnerabilityCount
| order by VMName asc
```
