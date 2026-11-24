# Security for AI – MITRE ATLAS Detection Coverage

## Overview

This collection of KQL queries provides insights into observed AI security detection coverage in Microsoft Defender XDR against the [MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial-Intelligence Systems) framework.

The queries combine the official MITRE ATLAS technique catalogue with Microsoft Defender XDR security alerts to identify observed attack techniques, analyze associated evidence, assess detection coverage, and visualize the results.

The collection is intended to support security assessments, threat hunting, detection engineering, and security operations.

## Objectives

- Identify AI security alerts and their associated MITRE ATLAS techniques.
- Enrich detection coverage with AI agent information and alert evidence.
- Measure observed detection coverage across tactics, techniques, and sub-techniques.
- Analyze direct and inherited parent technique coverage.
- Identify alerts without corresponding MITRE ATLAS mappings.
- Visualize detection coverage and alert activity over time.
- Export observed detection coverage to the MITRE ATLAS Navigator.

## Data Sources

| Data Source | Description |
|---|---|
| AlertInfo | Security alerts, detection titles, severity, categories, and technique mappings. |
| AlertEvidence | Associated entities, evidence categories, AI agents, and hosting platforms. |
| MITRE ATLAS STIX JSON | Official catalogue of AI attack tactics, techniques, and sub-techniques. |

The MITRE ATLAS catalogue is dynamically retrieved from the official MITRE ATLAS GitHub repository using the KQL `externaldata()` operator.

The queries focus on Microsoft Defender XDR alerts from the following detection sources:

- Security for AI
- Microsoft Defender for AI Services

## Query Collection

The queries are numbered to provide a logical assessment workflow. Each query is standalone and can also be executed independently.

### Phase 1 – Discover and Enrich

Establish observed detection coverage and identify associated AI assets and evidence.

| # | Query | Description |
|---|---|---|
| 01 | [Detection Coverage](MDXDR-SecurityForAI-MITRE-ATLAS-01-DetectionCoverage.md) | Maps Microsoft Defender XDR alerts to the official MITRE ATLAS technique catalogue. |
| 02 | [Enriched Detection Coverage](MDXDR-SecurityForAI-MITRE-ATLAS-02-EnrichedDetectionCoverage.md) | Enriches detection coverage with evidence categories, AI agents, entity types, and hosting platforms. |

### Phase 2 – Measure

Quantify observed detection coverage across the MITRE ATLAS framework.

| # | Query | Description |
|---|---|---|
| 03 | [Overall Coverage Statistics](MDXDR-SecurityForAI-MITRE-ATLAS-03-OverallCoverageStatistics.md) | Calculates overall observed detection coverage for techniques and sub-techniques. |
| 04 | [Coverage Statistics by Tactic](MDXDR-SecurityForAI-MITRE-ATLAS-04-CoverageStatisticsByTactic.md) | Calculates observed detection coverage and coverage percentages for individual tactics. |

### Phase 3 – Analyze

Analyze technique relationships and the completeness of alert mappings.

| # | Query | Description |
|---|---|---|
| 05 | [Parent Technique Coverage](MDXDR-SecurityForAI-MITRE-ATLAS-05-ParentTechniqueCoverage.md) | Evaluates direct parent technique observations and inherited observations from associated sub-techniques. |
| 06 | [Unmapped Alerts](MDXDR-SecurityForAI-MITRE-ATLAS-06-UnmappedAlerts.md) | Identifies AI security alerts without matching MITRE ATLAS technique identifiers. |

### Phase 4 – Visualize

Visualize observed detection coverage and historical detection activity.

| # | Query | Description |
|---|---|---|
| 07 | [Coverage Visualization by Tactic](MDXDR-SecurityForAI-MITRE-ATLAS-07-CoverageVisualizationByTactic.md) | Displays observed and not-observed techniques per tactic using a stacked column chart. |
| 08 | [Coverage Percentage Visualization](MDXDR-SecurityForAI-MITRE-ATLAS-08-CoveragePercentageVisualization.md) | Displays observed detection coverage percentages per tactic using a column chart. |
| 09 | [Detection Activity over Time](MDXDR-SecurityForAI-MITRE-ATLAS-09-DetectionActivityOverTime.md) | Visualizes AI security alert activity, observed techniques, and detection titles over time. |

### Phase 5 – Export

Export observed detection coverage for visualization in the MITRE ATLAS Navigator.

| # | Query | Description |
|---|---|---|
| 10 | [MITRE ATLAS Navigator Export](MDXDR-SecurityForAI-MITRE-ATLAS-10-NavigatorExport.md) | Generates a JSON layer for visualizing observed detection coverage in the MITRE ATLAS Navigator. |

## Assessment Methodology

The queries follow a consistent methodology:

1. Retrieve the official MITRE ATLAS technique catalogue.
2. Collect AI security alerts from Microsoft Defender XDR.
3. Extract native MITRE ATLAS technique identifiers from the alert metadata.
4. Correlate the observed technique identifiers with the official catalogue.
5. Enrich the results with associated alert evidence where applicable.
6. Calculate observed detection coverage.
7. Visualize and export the results.

## Understanding Detection Coverage

It is important to distinguish between observed, available, and effective detection coverage.

| Coverage Type | Description |
|---|---|
| Observed Detection Coverage | Techniques associated with actual security alerts within the selected time range. |
| Available Detection Coverage | Techniques for which the security platform provides detection capabilities. |
| Effective Detection Coverage | Detection capabilities validated through controlled security testing or attack simulations. |

This query collection primarily measures **observed detection coverage**.

A technique classified as **Not Observed** does not necessarily indicate a detection gap. It indicates that no corresponding alert was identified within the available alert data and selected hunting time range.

Similarly, an observed sub-technique does not imply complete detection coverage of its parent technique.

AI security alerts without MITRE ATLAS mappings may still contain valid MITRE ATT&CK mappings.

## Getting Started

1. Open the [Microsoft Defender portal](https://security.microsoft.com/).
2. Navigate to **Advanced Hunting**.
3. Select the desired hunting time range.
4. Execute the queries in the recommended order.
5. Review the results in the context of your AI environment and deployed security capabilities.

All queries are standalone and do not require the successful execution of preceding queries.

For consistent coverage comparisons, use the same hunting time range across all queries.

## MITRE ATLAS Navigator

The Navigator Export query generates a JSON layer that can be imported into the [MITRE ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/).

The resulting matrix provides a visual representation of observed and not-observed MITRE ATLAS techniques, including associated alert information.

### Export and Import Instructions

1. Execute query 10 – MITRE ATLAS Navigator Export.
2. Copy the generated JSON from the `NavigatorLayer` column.
3. Save the JSON content to a file, for example:

   `MicrosoftDefenderXDR-ATLAS-Coverage.json`

4. Open the MITRE ATLAS Navigator.
5. Import the JSON file as an existing layer.
6. Explore the observed detection coverage across the MITRE ATLAS matrix.

Review the exported information before sharing it externally, as it may contain organization-specific security detection information.

## Considerations and Limitations

- Results depend on available alert data, data retention, and the selected Advanced Hunting time range.
- Detection coverage depends on the technique mappings provided in Microsoft Defender XDR alert metadata.
- The official MITRE ATLAS catalogue is retrieved dynamically and may change over time.
- Coverage percentages are calculated against the retrieved MITRE ATLAS catalogue and do not consider the applicability of individual techniques to the assessed AI environment.
- Techniques associated with multiple tactics may appear under each applicable tactic.
- An individual alert may be associated with multiple techniques.
- Parent technique observations inherited from sub-techniques do not imply complete parent technique coverage.
- Alerts without MITRE ATLAS mappings may contain MITRE ATT&CK mappings.
- AI agent information depends on the availability of associated alert evidence.
- Observed detection coverage should not be interpreted as a complete assessment of AI security posture or detection effectiveness.

## Validation

All 10 KQL queries were successfully execution-tested in Microsoft Defender XDR Advanced Hunting on November 24, 2026.

## References

### MITRE ATLAS

- [MITRE ATLAS](https://atlas.mitre.org/)
- [MITRE ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [MITRE ATLAS Data Repository](https://github.com/mitre-atlas/atlas-data)
- [MITRE ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/)
- [MITRE ATLAS Navigator Data Repository](https://github.com/mitre-atlas/atlas-navigator-data)
- [MITRE ATLAS STIX JSON Dataset](https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json)

### Microsoft Defender XDR and KQL

- [Microsoft Defender XDR Advanced Hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [AlertInfo Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table)
- [AlertEvidence Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table)
- [KQL externaldata Operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator)
- [KQL materialize Function](https://learn.microsoft.com/en-us/kusto/query/materialize-function)
- [KQL render Operator](https://learn.microsoft.com/en-us/kusto/query/render-operator)

## Author

Alex Verboon

- [GitHub](https://github.com/alexverboon)
- [Defender Resource Hub](https://defenderresourcehub.info/)
- [KQL Café](https://kqlcafe.com/)