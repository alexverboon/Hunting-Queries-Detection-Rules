---
title: "Azure VM MDE Onboarding Status"
description: |
  This query inventories Azure virtual machines in Microsoft Defender XDR Exposure Graph and reports their Microsoft Defender for Endpoint onboarding and sensor health status. Configure the Azure subscription IDs to include, then use the returned VM, resource group, operating system, and device details to review onboarding coverage.

status: "Stable"

queryType: "Audit"

risk: |
  Azure virtual machines that are not onboarded to Microsoft Defender for Endpoint, or whose sensors are unhealthy, may have reduced endpoint visibility and protection.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-exposuregraphnodes-table"

mitre: []

dataSources:
  - table: "ExposureGraphNodes"
    solution: "Microsoft Defender XDR"

version: "1.0"
created: "2026-10-23"
lastModified: "2026-10-23"
---

[![Status: Stable](https://img.shields.io/badge/status--Stable-22c55e.svg)]()
[![Type: Audit](https://img.shields.io/badge/type--Audit-3b82f6.svg)]()
[![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)]()

---

# Azure VM MDE Onboarding Status

## Query Information

### Description

This query inventories Azure virtual machines in Microsoft Defender XDR Exposure Graph and reports their Microsoft Defender for Endpoint onboarding and sensor health status. Configure the Azure subscription IDs to include, then use the returned VM, resource group, operating system, and device details to review onboarding coverage.

### Risk

Azure virtual machines that are not onboarded to Microsoft Defender for Endpoint, or whose sensors are unhealthy, may have reduced endpoint visibility and protection.

### Author

- **Name:** Alex Verboon
- **Link:** <https://github.com/alexverboon>

### References

- <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-exposuregraphnodes-table>

### Data Sources

| Table | Solution |
| ----- | -------- |
| `ExposureGraphNodes` | Microsoft Defender XDR |

---

## KQL Query

### Azure VM MDE Onboarding Status

```kql
// Configuration: Azure subscriptions to include
let vSubscriptionIds = dynamic([
    "00000000-0000-0000-0000-000000000000"
]);
// Azure VM inventory from Exposure Graph
ExposureGraphNodes
| where NodeLabel =~ "microsoft.compute/virtualmachines"
| where Categories has "virtual_machine"
// Extract Azure resource information
| extend AzureResourceId = tostring(EntityIds[0].id)
| extend
    SubscriptionId = extract(@"(?i)/subscriptions/([^/]+)", 1, AzureResourceId),
    ResourceGroup = extract(@"(?i)/resourcegroups/([^/]+)", 1, AzureResourceId)
// Filter subscriptions
| where SubscriptionId in~ (vSubscriptionIds)
// Extract VM attributes
| extend
    VMName = tostring(split(AzureResourceId, "/")[-1]),
    DeviceName = tostring(NodeProperties.rawData.deviceName),
    LastSeen = todatetime(NodeProperties.rawData.lastSeen),
    OnboardingStatus = tostring(NodeProperties.rawData.onboardingStatus),
    OSPlatform = tostring(NodeProperties.rawData.osPlatformFriendlyName),
    FirstSeenByInventory = todatetime(NodeProperties.rawData.firstSeenByInventory),
    DeviceGroup = tostring(NodeProperties.rawData.machineGroup),
    SensorHealthState = tostring(NodeProperties.rawData.sensorHealthState)
// Normalize hostname (remove DNS suffix)
| extend
    DeviceHostName = tolower(tostring(split(DeviceName, ".")[0]))
// Final inventory
| project
    SubscriptionId,
    ResourceGroup,
    VMName,
    DeviceName,
    DeviceHostName,
    OSPlatform,
    OnboardingStatus,
    SensorHealthState,
    DeviceGroup,
    FirstSeenByInventory,
    LastSeen,
    AzureResourceId 
| order by VMName asc
```
