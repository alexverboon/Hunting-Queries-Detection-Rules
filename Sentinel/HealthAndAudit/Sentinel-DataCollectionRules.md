---
title: "Azure Monitor Data Collection Rule Inventory"

description: |
  Azure Monitor data collection rules define how monitoring data is collected, transformed,
  and routed for supported scenarios. Reviewing them helps identify configuration gaps
  that could affect security data visibility. These audit queries provide easy access to
  a rule inventory and its configuration details in Microsoft Defender XDR advanced hunting.

status: "Stable"

queryType: "Audit"

risk: |
  Unexpected or misconfigured collection rules, transformations, or destinations may
  affect the visibility or routing of security data. Inventory results alone do not
  establish malicious activity or confirm that data is being collected.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-defender-use-custom-rules#use-arg-operator-for-azure-resource-graph-queries"
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/azure-monitor-data-explorer-proxy"
  - "https://learn.microsoft.com/en-us/azure/governance/resource-graph/reference/supported-tables-resources"
  - "https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/explore-resources"
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-structure"
  - "https://learn.microsoft.com/en-us/rest/api/monitor/data-collection-rules/get?view=rest-monitor-2024-03-11"

mitre: []

dataSources:
  - table: "Resources"
    solution: "Azure Resource Graph"

version: "1.0"
created: "2026-11-24"
lastModified: "2026-11-24"
---

![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg)
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Azure Monitor Data Collection Rule Inventory

## Query Information

### Description

Azure Monitor data collection rules define how monitoring data is collected, transformed,
and routed for supported scenarios. Reviewing them helps identify configuration gaps
that could affect security data visibility. These audit queries provide easy access to
a rule inventory and its configuration details in Microsoft Defender XDR advanced hunting.

### Execution and Scope

Run the queries in Microsoft Defender XDR advanced hunting using the `arg()`
cross-service operator. Results depend on the access available to the user and
include accessible rules across the query scope, not only rules associated with
Microsoft Sentinel. Microsoft documents a 1,000-record limit for the `arg` portion
of Azure Monitor Logs cross-service queries; verify applicable limits in your
environment. These are configuration snapshots, not historical events, and neither
query applies a time filter.

The detailed query's individual stream, flow destination, and Log Analytics
destination fields select only the first corresponding array elements. Inspect the
full `DataFlows` and `Destinations` columns for additional entries. Properties may
be absent depending on the rule's configuration; their availability in Resource
Graph should be checked in the tenant.

### Risk

Unexpected or misconfigured collection rules, transformations, or destinations may
affect the visibility or routing of security data. Inventory results alone do not
establish malicious activity or confirm that data is being collected.

### Author

- **Name:** Alex Verboon
- **Link:** [https://github.com/alexverboon](https://github.com/alexverboon)

### References

- [Azure Resource Graph queries in advanced hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-defender-use-custom-rules#use-arg-operator-for-azure-resource-graph-queries)
- [Azure Monitor Logs cross-service queries](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/azure-monitor-data-explorer-proxy)
- [Azure Resource Graph supported tables and resource types](https://learn.microsoft.com/en-us/azure/governance/resource-graph/reference/supported-tables-resources)
- [Explore Azure resources with Resource Graph](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/explore-resources)
- [Data collection rule structure](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-structure)
- [Data collection rule REST API](https://learn.microsoft.com/en-us/rest/api/monitor/data-collection-rules/get?view=rest-monitor-2024-03-11)

### Data Sources

| Table | Solution |
| --- | --- |
| `Resources` | Azure Resource Graph |

### Investigation Guidance

Review unexpected rule configurations against the intended collection, transformation,
and destination design. Check associated resources and actual ingestion separately
when investigating potential gaps.

---

## KQL Query

### List data collection rules

```kql
// List DCR Rules
arg("").Resources
| where type =~ "microsoft.insights/datacollectionrules"
| project
    Name = name,
    Kind = kind,
    ResourceGroup = resourceGroup,
    SubscriptionId = subscriptionId,
    Location = location,
    ImmutableId = properties.immutableId
| order by Name asc
```

### Show rule details

```kql
// Show all the details.

arg("").Resources
| where type =~ "microsoft.insights/datacollectionrules"
| project DCRName = name,
    Kind = kind,
    ProvisioningState = properties.provisioningState,
    InputStream = properties.dataFlows[0].streams[0],
    OutputStream = properties.dataFlows[0].outputStream,
    TransformKql = properties.dataFlows[0].transformKql,
    FlowDestination = properties.dataFlows[0].destinations[0],
    LAWName = properties.destinations.logAnalytics[0].name,
    LAWWorkspaceId = properties.destinations.logAnalytics[0].workspaceId,
    LAWResourceId = properties.destinations.logAnalytics[0].workspaceResourceId,
    DataCollectionEndpointId = properties.dataCollectionEndpointId,
    ImmutableId = properties.immutableId,
    SubscriptionId = subscriptionId,
    ResourceGroup = resourceGroup,
    Location = location,
    StreamDeclarations = properties.streamDeclarations,
    DataSources = properties.dataSources,
    DataFlows = properties.dataFlows,
    Destinations = properties.destinations,
    AgentSettings = properties.agentSettings,
    Endpoints = properties.endpoints,
    ResourceId = id
| order by DCRName asc
```
