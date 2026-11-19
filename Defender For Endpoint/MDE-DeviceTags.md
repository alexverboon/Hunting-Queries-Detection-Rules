---
title: "Defender for Endpoint - Device Tags"

description: |
  Inventories manual, dynamic, and registry device tags in Defender XDR advanced hunting. The queries show tags alongside device details, summarize raw tag values by source, and list unique tag names across all three sources.

# Options: Draft | InProgress | Stable | Deprecated
status: "Draft"

# Options: Detection | ThreatHunting | ThreatIntelligence | Audit | ExposureManagement | Vulnerability
queryType: "Audit"

risk: |
  Missing or inconsistent tags can cause devices to be overlooked in reviews or workflows that rely on those tags. These results do not establish device compliance, policy enforcement, or malicious activity.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table"

dataSources:
  - table: "DeviceInfo"
    solution: "Microsoft Defender for Endpoint / Microsoft Defender XDR"

version: "2.0"
created: "2026-11-19"
lastModified: "2026-11-19"
---

<!-- STATUS: uncomment the badge matching the status above -->
![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg)
<!-- ![Status: In Progress](https://img.shields.io/badge/status-in%20progress-eab308.svg) -->
<!-- ![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg) -->
<!-- ![Status: Deprecated](https://img.shields.io/badge/status-deprecated-ef4444.svg) -->

<!-- QUERY TYPE: uncomment the badge matching the queryType above -->
<!-- ![Type: Detection](https://img.shields.io/badge/type-detection-ef4444.svg) -->
<!-- ![Type: Threat Hunting](https://img.shields.io/badge/type-threat%20hunting-f97316.svg) -->
<!-- ![Type: Threat Intelligence](https://img.shields.io/badge/type-threat%20intelligence-a855f7.svg) -->
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
<!-- ![Type: Exposure Management](https://img.shields.io/badge/type-exposure%20management-8b5cf6.svg) -->
<!-- ![Type: Vulnerability](https://img.shields.io/badge/type-vulnerability-eab308.svg) -->

![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Defender for Endpoint - Device Tags

## Query Information

### Description

The three Defender XDR queries show tags alongside device details, summarize distinct raw tag field values by source, and list unique individual tag names across all sources. They do not filter by time or select the latest record per device, so results can include historical tags and repeated devices.

### Risk

Missing or inconsistent tags can cause devices to be overlooked in reviews or workflows that rely on those tags. These results do not establish device compliance, policy enforcement, or malicious activity.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [DeviceInfo table in Defender XDR advanced hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)

### Data Sources

| Table | Solution |
| --- | --- |
| `DeviceInfo` | Microsoft Defender for Endpoint / Microsoft Defender XDR |

### Execution Notes

Run each query separately in Defender XDR advanced hunting. The unique-tag query expands manual and dynamic tag arrays but treats each nonempty `RegistryDeviceTag` value as one tag.

---

## KQL Query

### Device Tag Inventory

```kql
DeviceInfo
| project DeviceName, OnboardingStatus, DeviceCategory, MachineGroup,
          DeviceManualTags, DeviceDynamicTags, RegistryDeviceTag
```

### Distinct Raw Tag Values by Source

Returns distinct nonempty field values by source. A raw field value may contain multiple tags.

```kql
DeviceInfo
| summarize
    ManualTags = make_set_if(DeviceManualTags, isnotempty(DeviceManualTags), 10000),
    DynamicTags = make_set_if(DeviceDynamicTags, isnotempty(DeviceDynamicTags), 10000),
    RegTags = make_set_if(RegistryDeviceTag, isnotempty(RegistryDeviceTag), 10000)
```

### Unique Tag Names Across Sources

```kql
let NormalizeTags = (rawTags: string) {
    let parsed = parse_json(rawTags);
    iff(isnotnull(array_length(parsed)), parsed, pack_array(tostring(parsed)))
};
let ManualTags =
    DeviceInfo
    | mv-expand Tag = NormalizeTags(DeviceManualTags)
    | project Tag = tostring(Tag);
let DynamicTags =
    DeviceInfo
    | mv-expand Tag = NormalizeTags(DeviceDynamicTags)
    | project Tag = tostring(Tag);
let RegistryTags =
    DeviceInfo
    | project Tag = RegistryDeviceTag;
ManualTags
| union DynamicTags, RegistryTags
| where isnotempty(Tag)
| summarize UniqueTags = make_set(Tag)
```





