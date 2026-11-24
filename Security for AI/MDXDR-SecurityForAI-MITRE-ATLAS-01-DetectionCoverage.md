---
title: Security for AI - MITRE ATLAS Observed Detection Coverage
description: Matches native ATLAS technique IDs in AI security alerts to the official catalogue and retains techniques without observed alerts.
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
- https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json
- https://learn.microsoft.com/en-us/kusto/query/externaldata-operator
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
# Security for AI - MITRE ATLAS Observed Detection Coverage

## Query Information

### Description

Matches native ATLAS technique IDs in AI security alerts to the official catalogue and retains techniques without observed alerts.

### Risk

An absence of observed alerts can conceal untested detection capabilities, telemetry gaps or incomplete technique mappings. Results do not establish that a technique is undetectable or that an alert represents confirmed malicious activity.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [AlertInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table)
- [Advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [MITRE ATLAS STIX catalogue](https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json)
- [Kusto externaldata operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator)

### Data Sources

| Table | Solution |
| --- | --- |
| `AlertInfo` | Microsoft Defender XDR |

External reference: official ATLAS STIX JSON retrieved at execution time.

### Investigation Guidance

Use Microsoft Defender XDR Advanced Hunting. The query uses the selected hunting time range and available data; no additional lookback is imposed. Native ATLAS IDs and the two detection source values are based on tenant observations. Public schema documentation describes AttackTechniques as ATT&CK metadata; ATLAS values are not guaranteed in every tenant. Distinct counts using dcount() are approximate. No fixed ATT&CK or ATLAS technique mapping is assigned because this query reports mappings dynamically rather than detecting a specific technique.



Validation: The corresponding query was reported working in the author’s tenant. All files remain Draft pending repository review.

---
## KQL Query

```kql
let MitreAtlas =
    externaldata(objects: dynamic)
    [
        @"https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"
    ]
    with (format="multijson")
    | mv-expand objects
    | where objects.type == "attack-pattern"
    | mv-expand Reference = objects.external_references
    | where Reference.source_name == "mitre-atlas"
    | project
        TechniqueId = tostring(Reference.external_id),
        TechniqueName = tostring(objects.name),
        Description = tostring(objects.description),
        Tactics = objects.kill_chain_phases,
        IsSubTechnique = tobool(objects.x_mitre_is_subtechnique),
        Url = tostring(Reference.url),
        Created = todatetime(objects.created),
        Modified = todatetime(objects.modified)
    | mv-expand Tactics
    | extend Tactic = tostring(Tactics.phase_name)
    | project-away Tactics;
let AIAlertCoverage =
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
    | summarize
        AlertCount = dcount(AlertId),
        DetectionCount = dcount(Title),
        DetectionTitles = make_set(Title),
        DetectionSources = make_set(DetectionSource),
        ServiceSources = make_set(ServiceSource),
        Categories = make_set(Category),
        Severities = make_set(Severity),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp)
        by TechniqueId;
MitreAtlas
| join kind=leftouter AIAlertCoverage on TechniqueId
| extend
    AlertCount = coalesce(AlertCount, 0),
    DetectionCount = coalesce(DetectionCount, 0)
| extend CoverageStatus = iff(
    AlertCount > 0, "Observed", "Not Observed")
| project
    Tactic, TechniqueId, TechniqueName, IsSubTechnique,
    CoverageStatus, AlertCount, DetectionCount, DetectionTitles,
    DetectionSources, ServiceSources, Categories, Severities,
    FirstSeen, LastSeen, Description, Url, Created, Modified
| order by AlertCount desc, Tactic asc, TechniqueId asc
```
