---
title: Security for AI - MITRE ATLAS Enriched Observed Detection Coverage
description: Enriches observed ATLAS coverage with evidence categories, associated AI agent identifiers, names and hosting platforms.
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
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table
- https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json
- https://learn.microsoft.com/en-us/kusto/query/externaldata-operator
dataSources:
- table: AlertInfo
  solution: Microsoft Defender XDR
- table: AlertEvidence
  solution: Microsoft Defender XDR
version: '1.0'
created: '2026-11-24'
lastModified: '2026-11-24'
---
![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg)
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---
# Security for AI - MITRE ATLAS Enriched Observed Detection Coverage

## Query Information

### Description

Enriches observed ATLAS coverage with evidence categories, associated AI agent identifiers, names and hosting platforms.

### Risk

An absence of observed alerts can conceal untested detection capabilities, telemetry gaps or incomplete technique mappings. Results do not establish that a technique is undetectable or that an alert represents confirmed malicious activity.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [AlertInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table)
- [Advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [AlertEvidence schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table)
- [MITRE ATLAS STIX catalogue](https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json)
- [Kusto externaldata operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator)

### Data Sources

| Table | Solution |
| --- | --- |
| `AlertInfo` | Microsoft Defender XDR |
| `AlertEvidence` | Microsoft Defender XDR |

External reference: official ATLAS STIX JSON retrieved at execution time.

### Investigation Guidance

Use Microsoft Defender XDR Advanced Hunting. The query uses the selected hunting time range and available data; no additional lookback is imposed. Native ATLAS IDs and the two detection source values are based on tenant observations. Public schema documentation describes AttackTechniques as ATT&CK metadata; ATLAS values are not guaranteed in every tenant. Distinct counts using dcount() are approximate. No fixed ATT&CK or ATLAS technique mapping is assigned because this query reports mappings dynamically rather than detecting a specific technique.

Agent properties in AdditionalFields are tenant-observed, not guaranteed by the public schema. An associated agent is not necessarily compromised. Both materialization steps are retained.

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
let AIEvidenceCoverage =
    AIAlertCoverage
    | mv-expand AlertId = AlertIds to typeof(string)
    | project TechniqueId, AlertId
    | join kind=inner (
        AlertEvidence
        | extend AF = parse_json(AdditionalFields)
        | project
            AlertId,
            EvidenceCategories = parse_json(Categories),
            EntityType,
            AgentName = tostring(AF.AgentName),
            AgentId = tostring(AF.AgentId),
            AgentPlatform = tostring(AF.HostingPlatformType)
    ) on AlertId
    | summarize
        EvidenceCategories = make_set(EvidenceCategories),
        EntityTypes = make_set(EntityType),
        AgentNames = make_set_if(AgentName, isnotempty(AgentName)),
        AgentIds = make_set_if(AgentId, isnotempty(AgentId)),
        AgentPlatforms = make_set_if(AgentPlatform, isnotempty(AgentPlatform))
        by TechniqueId
    | extend AffectedAgents = array_length(AgentIds);
let EnrichedCoverage = materialize(
    AIAlertCoverage
    | join kind=leftouter AIEvidenceCoverage on TechniqueId
    | project
        TechniqueId,
        AlertCount,
        DetectionTitles,
        EvidenceCategories,
        EntityTypes,
        AgentNames,
        AgentIds,
        AgentPlatforms,
        AffectedAgents,
        AlertIds
);
MitreAtlas
| join kind=leftouter EnrichedCoverage on TechniqueId
| extend
    AlertCount = coalesce(AlertCount, 0),
    AffectedAgents = coalesce(AffectedAgents, 0)
| extend CoverageStatus = iff(
    AlertCount > 0, "Observed", "Not Observed")
| project
    Tactic,
    TechniqueId,
    TechniqueName,
    IsSubTechnique,
    CoverageStatus,
    AlertCount,
    DetectionTitles,
    EvidenceCategories,
    EntityTypes,
    AffectedAgents,
    AgentNames,
    AgentIds,
    AgentPlatforms,
    AlertIds,
    Description,
    Url,
    Created,
    Modified
| order by AlertCount desc, Tactic asc, TechniqueId asc
```
