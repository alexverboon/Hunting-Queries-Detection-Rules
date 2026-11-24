---
title: Security for AI - MITRE ATLAS Detection Activity over Time
description: Charts daily distinct alerts, ATLAS technique IDs and detection titles for AI alerts containing native ATLAS mappings.
status: Draft
queryType: Audit
risk: An absence of observed alerts can conceal untested detection capabilities, telemetry gaps or incomplete technique mappings. Results do not establish that a technique is undetectable or that an alert represents confirmed malicious activity.
author:
  name: Alex Verboon
  link: https://github.com/alexverboon
references:
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
- https://atlas.mitre.org/
dataSources:
- table: AlertInfo
  solution: Microsoft Defender XDR
version: '1.0'
created: '2026-11-24'
lastModified: '2026-11-24'
---
![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg)
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---
# Security for AI - MITRE ATLAS Detection Activity over Time

## Query Information

### Description

Charts daily distinct alerts, ATLAS technique IDs and detection titles for AI alerts containing native ATLAS mappings.

### Risk

An absence of observed alerts can conceal untested detection capabilities, telemetry gaps or incomplete technique mappings. Results do not establish that a technique is undetectable or that an alert represents confirmed malicious activity.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [AlertInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table)
- [Advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [MITRE ATLAS](https://atlas.mitre.org/)

### Data Sources

| Table | Solution |
| --- | --- |
| `AlertInfo` | Microsoft Defender XDR |

### Investigation Guidance

Use Microsoft Defender XDR Advanced Hunting. The query uses the selected hunting time range and available data; no additional lookback is imposed. Native ATLAS IDs and the two detection source values are based on tenant observations. Public schema documentation describes AttackTechniques as ATT&CK metadata; ATLAS values are not guaranteed in every tenant. Distinct counts using dcount() are approximate. No fixed ATT&CK or ATLAS technique mapping is assigned because this query reports mappings dynamically rather than detecting a specific technique.

Days with no matching alerts are omitted. This query does not validate IDs against the catalogue.

Validation: Proposed query; execution and output have not yet been validated in a tenant. All files remain Draft pending repository review.

---
## KQL Query

```kql
let AIAlertActivity = materialize(
    AlertInfo
    | where DetectionSource in (
        "Security for AI",
        "Microsoft Defender for AI Services"
    )
    | summarize arg_max(Timestamp, *) by AlertId
    | extend TechniqueIds = extract_all(
        @"(AML\.T\d{4}(?:\.\d{3})?)",
        tostring(AttackTechniques))
    | mv-expand TechniqueId = TechniqueIds to typeof(string)
    | where isnotempty(TechniqueId)
);
AIAlertActivity
| summarize AlertCount = dcount(AlertId),
    ObservedTechniques = dcount(TechniqueId),
    DetectionCount = dcount(Title)
    by bin(Timestamp, 1d)
| order by Timestamp asc
| render timechart
```
