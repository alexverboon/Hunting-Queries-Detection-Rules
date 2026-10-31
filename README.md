# KQL Queries for Microsoft Security

This repository collects KQL examples for security hunting, detections, auditing, and reporting across Microsoft security products and related data sources. Use them as starting points: verify table availability, schema, permissions, retention, and assumptions in your own environment before relying on results.

## Find Queries

- **MITRE ATT&CK:** [Technique mapping](./MITRE%20ATT%26CK/mapping.md)
- **Defender:** [XDR](./Defender%20XDR/), [Endpoint](./Defender%20For%20Endpoint/), [Identity](./Defender%20For%20Identity/), [Office 365](./Defender%20For%20Office%20365/), [Cloud Apps](./Defender%20For%20Cloud%20Apps/), [Cloud](./Defender%20For%20Cloud/), [IoT](./Defender4IoT/), and [External Attack Surface Management](./Defender%20External%20Attack%20Surface%20Management/)
- **Identity and productivity:** [Entra ID](./Entra%20ID/), [Active Directory](./ActiveDirectory/), [Windows LAPS](./Windows%20LAPS/), [Office 365](./Office365/), [Copilot](./Copilot/), and [Power Platform](./PowerPlatform/)
- **Azure and other sources:** [Azure DevOps](./AzureDevOps/), [Azure Arc](./AzureArc/), [Azure Resource Graph](./AzureResourceGraph/), [Automation Accounts](./AutomationAccounts/), [Exposure Management](./ExposureManagement/), [Microsoft Purview](./Microsoft%20Purview/), [Microsoft Sentinel](./Sentinel/), [Threat Hunting](./Threat%20Hunting/), [App Governance](./AppGovernance/), [External Data](./ExternalData/), and [Graph Activity](./GraphActivity/)

## Query Format

New and migrated query files use [`templatev2.md`](./templatev2.md). Its front matter records summary metadata; the body explains the query and contains the KQL.

- **Status:** `Draft` means new or not yet reviewed; `InProgress` means actively being developed or tested; `Stable` means reviewed for use; `Deprecated` means no longer recommended.
- **Query type:** `Detection`, `ThreatHunting`, `ThreatIntelligence`, `Audit`, `ExposureManagement`, or `Vulnerability` describes the query's purpose.
- **Data sources:** list every table used, including tables in joins and subqueries. Include references and defensible ATT&CK mappings; use ATLAS separately for relevant AI-related queries.
- **Optional guidance:** document false positives, investigation steps, and detection-rule settings when applicable.

Use the [KQL query authoring skill](./.github/skills/kql-query-authoring/SKILL.md) to create a new query file from KQL, or the [KQL Query Markdown migration skill](./.github/skills/kql-query-markdown-migration/SKILL.md) to convert an existing file in place.

## License and Credits

This repository is licensed under the [MIT License](./LICENSE). Retain the license and copyright notice when redistributing covered material. Some queries may include third-party contributions or material adapted from external sources; retain their attribution and follow any source-specific terms noted in the query.

The repository's content structure was inspired by [Bert-Jan's KQL repository](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules). Query authors and sources are credited where known. Some queries may be adapted from Microsoft documentation or other published material; consult each query's references for provenance.

Questions or corrections can be submitted through [GitHub Issues](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/issues).
