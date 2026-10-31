---
title: "[Query title]"

description: |
  [In a few sentences, explain what the query detects, hunts for, or summarizes.
  Include the relevant behavior, entities, and why the results are useful.]

# Options: Draft | InProgress | Stable | Deprecated
status: "Draft"

# Options: Detection | ThreatHunting | ThreatIntelligence | Audit | ExposureManagement | Vulnerability
queryType: "ThreatHunting"

risk: |
  [Describe the security impact or risk represented by the query results.]

author:
  name: "[Author name]"
  link: "[Author profile URL]"

references:
  - "[Documentation, advisory, or research URL]"

mitre:
  - id: "[Technique ID, e.g. T1110.003]"
    name: "[Technique name]"
    url: "[https://attack.mitre.org/techniques/...]"

# Optional: include only for relevant AI-related queries; use official MITRE ATLAS mappings.
mitreAtlas:
  - id: "[ATLAS technique ID]"
    name: "[Technique name]"
    url: "[https://atlas.mitre.org/techniques/...]"

# Add one entry for each table used by the query, including joined or subqueried tables.
dataSources:
  - table: "[Table name]"
    solution: "[Product or solution]"

version: "1.0"
created: "[YYYY-MM-DD]"
lastModified: "[YYYY-MM-DD]"
---

<!-- STATUS: uncomment the badge matching the status above -->
![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg)
<!-- ![Status: In Progress](https://img.shields.io/badge/status-in%20progress-eab308.svg) -->
<!-- ![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg) -->
<!-- ![Status: Deprecated](https://img.shields.io/badge/status-deprecated-ef4444.svg) -->

<!-- QUERY TYPE: uncomment the badge matching the queryType above -->
<!-- ![Type: Detection](https://img.shields.io/badge/type-detection-ef4444.svg) -->
![Type: Threat Hunting](https://img.shields.io/badge/type-threat%20hunting-f97316.svg)
<!-- ![Type: Threat Intelligence](https://img.shields.io/badge/type-threat%20intelligence-a855f7.svg) -->
<!-- ![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg) -->
<!-- ![Type: Exposure Management](https://img.shields.io/badge/type-exposure%20management-8b5cf6.svg) -->
<!-- ![Type: Vulnerability](https://img.shields.io/badge/type-vulnerability-eab308.svg) -->

![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# [Query title]

## Query Information

### Description

[Explain what the query does, what behavior or activity it identifies, and how to interpret the results.]

### Risk

[Explain why the detected activity matters and what an analyst should investigate.]

### Author

- **Name:** [Author name]
- **Link:** [Author profile URL]

### References

- [Reference title](https://example.com)

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| [T0000.000] | [Technique name] | [https://attack.mitre.org/techniques/T0000/000/] |

### MITRE ATLAS Technique(s) (Optional; AI-related queries)

| Technique ID | Title | Link |
| --- | --- | --- |
| [ATLAS technique ID] | [Technique name] | [https://atlas.mitre.org/techniques/...] |

### Data Sources

Add one row for each table used by the query, including joined or subqueried tables.

| Table | Solution |
| --- | --- |
| `[Table name]` | [Product or solution] |

### False Positives and Tuning (Optional)

[Describe expected benign matches and any recommended filters, exclusions, or tuning.]

### Investigation Guidance (Optional)

[Describe what an analyst should validate and which related activity or context to review.]

### Detection Rule Settings (Optional; detection queries only)

| Setting | Value |
| --- | --- |
| Severity | [Informational, Low, Medium, or High] |
| Run frequency | [For example, 1 hour] |
| Query period | [For example, 1 day] |
| Alert suppression | [Optional; specify duration or None] |

---

## KQL Query

```kql
let lookback = 7d;
YourTableName
| where TimeGenerated >= ago(lookback)
// Add filters for the behavior you want to find.
| project *
| sort by TimeGenerated desc
```

<!-- Optional: add focused variants, enrichment, or visualizations below. -->