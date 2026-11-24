---
title: Security for AI - MITRE ATLAS Navigator JSON Export
description: Produces a JSON layer with binary observed coverage scores, alert counts and detection titles for import into ATLAS Navigator.
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
- https://mitre-atlas.github.io/atlas-navigator/
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
# Security for AI - MITRE ATLAS Navigator JSON Export

## Query Information

### Description

Produces a JSON layer with binary observed coverage scores, alert counts and detection titles for import into ATLAS Navigator.

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
- [ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/)

### Data Sources

| Table | Solution |
| --- | --- |
| `AlertInfo` | Microsoft Defender XDR |

External reference: official ATLAS STIX JSON retrieved at execution time.

### Investigation Guidance

Use Microsoft Defender XDR Advanced Hunting. The query uses the selected hunting time range and available data; no additional lookback is imposed. Native ATLAS IDs and the two detection source values are based on tenant observations. Public schema documentation describes AttackTechniques as ATT&CK metadata; ATLAS values are not guaranteed in every tenant. Distinct counts using dcount() are approximate. No fixed ATT&CK or ATLAS technique mapping is assigned because this query reports mappings dynamically rather than detecting a specific technique.

Copy the NavigatorLayer value (not an enclosing CSV/JSON export wrapper) into a .json file and import at https://mitre-atlas.github.io/atlas-navigator/. Review detection titles before sharing. Layer version compatibility, tactic names and output truncation must be checked during import.

Validation: Proposed query; execution and output have not yet been validated in a tenant. All files remain Draft pending repository review.

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
let AIAlertCoverage = materialize(
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
        AlertIds = make_set(AlertId),
        DetectionTitles = make_set(Title)
        by TechniqueId
);
MitreAtlas
| join kind=leftouter AIAlertCoverage on TechniqueId
| extend AlertCount = coalesce(AlertCount, 0)
| extend DetectionCount = coalesce(array_length(DetectionTitles), 0)
| extend CoverageScore = iff(AlertCount > 0, 100, 0),
    CoverageColor = iff(AlertCount > 0, "#31a354", "#d9d9d9")
| extend Comment = strcat(TechniqueName, " | Alerts: ", tostring(AlertCount),
    " | Detection Count: ", tostring(DetectionCount),
    " | Detection Titles: ", tostring(DetectionTitles))
| extend Technique = bag_pack(
    "techniqueID", TechniqueId, "tactic", Tactic,
    "score", CoverageScore, "color", CoverageColor,
    "comment", Comment, "enabled", true, "showSubtechniques", true)
| summarize Techniques = make_list(Technique)
| extend NavigatorLayer = bag_pack(
    "name", "Microsoft Defender XDR - MITRE ATLAS Coverage",
    "description", "Observed AI security detection coverage based on Microsoft Defender XDR alerts",
    "domain", "atlas-atlas",
    "versions", bag_pack("navigator", "5.3.2", "layer", "4.5"),
    "techniques", Techniques,
    "gradient", bag_pack("colors", dynamic(["#d9d9d9", "#31a354"]), "minValue", 0, "maxValue", 100),
    "legendItems", pack_array(bag_pack("label", "Observed", "color", "#31a354"),
        bag_pack("label", "Not Observed", "color", "#d9d9d9")),
    "hideDisabled", false, "showTacticRowBackground", false)
| project NavigatorLayer = tostring(NavigatorLayer)
```
