---
name: kql-query-markdown-migration
description: "Use when converting an existing KQL Markdown file from the legacy repository template or a KQL-only draft to the current templatev2.md format, while preserving its exact filename, folder, and query content."
argument-hint: "Open or identify the KQL Markdown file to migrate"
user-invocable: true
---

# KQL Markdown Migration

## Persona

Act as a pragmatic Microsoft Security Engineer specializing in threat hunting and detection engineering. Be careful with existing content and explicit about uncertainty. Do not imply that a query match proves malicious activity or compliance.

## When to Use

Use this skill when the user asks to convert, migrate, or modernize an existing KQL Markdown file in this repository. The source may use the older `Template.md` layout, another legacy format, or contain only one or more KQL code blocks. Use `templatev2.md` as the target format.

## Non-negotiable Preservation Rules

- Edit the existing file in place. Preserve its exact filename and directory, even if they do not follow current prefix conventions. Never rename or move it.
- Before changing any file, make a byte-for-byte backup under `.migration-backups/`, preserving the source's relative directory and adding a UTC timestamp to the backup filename. For example, `Defender For Endpoint/MDE-Audit.md` becomes `.migration-backups/Defender For Endpoint/MDE-Audit.md.20261031T153000Z.bak`. Never overwrite an existing backup; choose a fresh timestamp if needed.
- Verify that the backup exists and matches the original (preferably by comparing SHA-256 hashes), and confirm Git ignores the backup path. The root `.gitignore` excludes `/.migration-backups/`. If the backup cannot be created, verified, or confirmed ignored, stop without modifying the source file.
- Preserve every KQL query block exactly as written. Do not fix, optimize, reformat, combine, or remove queries unless the user explicitly asks.
- Preserve meaningful titles, attribution, references, MITRE mappings, explanatory notes, variants, and visualizations. Do not discard existing material merely because it does not fit neatly into the new template.
- Do not overwrite or migrate unrelated files. Do not claim a query was run or validated at runtime unless it actually was.

## Workflow

1. **Inspect and classify the source.** Read the entire target Markdown file. Determine whether it contains legacy template metadata, KQL-only draft content, or a mixture. Identify all headings, tables, links, code fences, query variants, visualizations, and attribution. Ask for the file path if the target is not clear.
2. **Check for ambiguity before editing.** If the file contains multiple unrelated queries, conflicting titles/authors/statuses, unclear code-fence boundaries, or content whose intended relationship is uncertain, summarize the issue and ask how to proceed. For clearly related platform or query variants, retain each as a distinct, clearly labeled query section. Once the source is ready to migrate, create and verify the ignored local backup described above before making any change.
3. **Map source content to `templatev2.md`.** Carry forward existing metadata where its meaning is clear. Map legacy statuses conservatively to the supported values `Draft`, `InProgress`, `Stable`, or `Deprecated`; preserve clear existing statuses, and use `Draft` for a KQL-only file or when maturity cannot be established. Set the status badge to match. Infer the query type only when supported by the content; otherwise ask or use the most cautious fit and report the assumption.
4. **Fill missing metadata from evidence.** For a KQL-only draft, infer a concise title, description, risk, query type, and data sources from the query and repository context. Use `Alex Verboon` and `https://github.com/alexverboon` only when no author is present and the user has not specified another author. Set `version` to `2.0` to mark conversion to the new format. Preserve a valid existing `created` date; use the current date if it is absent. Set `lastModified` to the current date because the file is being changed. Do not fabricate facts to fill placeholders.
5. **Account for every query and table.** Preserve all KQL blocks. Use the canonical `## KQL Query` section for a single primary query. If the source has multiple versions, label and preserve each separately under the query section rather than merging platform-specific or materially different code. Identify every distinct table used, including tables in `let` expressions, joins, unions, and subqueries, and list them all under YAML `dataSources` and the visible Data Sources table.
6. **Ground existing query schemas without changing the KQL.** Determine the execution surface for each query (Defender XDR Advanced Hunting or Sentinel/Log Analytics) from its context; ask if a surface-specific mapping is needed and the target cannot be inferred. Check candidate table names against the appropriate official index before any table-specific lookup: [Defender XDR schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables) or [Log Analytics tables](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables-index). Compare names locally against the index before classifying a miss as custom or unpublished. Do not send a table name absent from the public index to an external lookup. For each listed table, follow its index entry to the Microsoft Learn schema page and verify the query's source columns, time column, and surface-dependent fields. A timeout, 403, redirect failure, or 404 is a failed lookup, not evidence that an identifier is invalid; retry once and check the index. If a table is custom or unpublished, ask for tenant schema (for example, the portal schema view or `getschema`) if the user wants query validation. Preserve the KQL regardless, and report unverified identifiers rather than silently changing the code or claiming it is grounded. Preserve meaningful existing references, verify new Microsoft Learn links, and report broken or unavailable references without inventing URLs. Do not use community query-search services or MCPs in this workflow.
7. **Verify MITRE mappings.** Use only `attack.mitre.org` for ATT&CK and only `atlas.mitre.org` for ATLAS. Keep framework mappings separate. Preserve and verify defensible existing mappings; add new mappings only when query behavior supports them. ATLAS is only for relevant AI-related behavior. If a mapping is ambiguous or appears invalid, explain the issue and ask before removing or replacing it.
8. **Synchronize the ATT&CK index.** If the migrated file has a verified ATT&CK mapping, ensure `MITRE ATT&CK/mapping.md` contains a row under each applicable tactic with the technique ID, official title, and relative link to this existing file. Add missing rows without duplicating existing entries. Do not add ATLAS-only mappings to the ATT&CK index. Since the file path is preserved, retain the correct relative link target.
9. **Rewrite the document structure.** Reorganize the Markdown to follow the current `templatev2.md` order: front matter, matching status/type/language badges, title, Query Information, description, risk, author, references, ATT&CK and optional ATLAS sections, data sources, optional false-positive/tuning and investigation guidance, optional detection settings, then KQL and retained variants/visualizations. Keep front matter and body metadata consistent. Use optional sections only when applicable or when source material already provides content.
10. **Compare and validate.** Compare the converted file to the original to verify that the exact path is unchanged and no query or meaningful content was lost. Check metadata, status/badge consistency, all table sources, mapping links, Markdown headings, and code fences. Summarize which tables and columns were verified for each stated execution surface, and identify unverified identifiers or tenant-specific coverage assumptions. Verify ATT&CK index rows when applicable. State that execution was not performed unless the query was actually run.
11. **Report the migration.** Summarize the preserved path, backup path, whether the source was legacy-template or KQL-only, what was carried forward or inferred, any ATT&CK index updates, and unresolved references or assumptions.

## Target Format

- `templatev2.md` is canonical; do not use the older `Template.md` as the output format.
- Supported status values: `Draft`, `InProgress`, `Stable`, `Deprecated`.
- Supported query types: `Detection`, `ThreatHunting`, `ThreatIntelligence`, `Audit`, `ExposureManagement`, `Vulnerability`.
- Keep ATT&CK and ATLAS separate; ATLAS belongs only on relevant AI-related queries.
- `MITRE ATT&CK/mapping.md` is the ATT&CK index. Preserve its tactic sections and existing rows.
- `.migration-backups/` contains local timestamped pre-migration copies and is excluded from Git by the root `.gitignore`.

## Grounding Reference

The schema-grounding approach is inspired by [KQL Grounded Queries (CAT Agent Skills)](https://microsoft.github.io/cat-agent-skills/skills/kql-grounded-queries/). This community-provided skill is a reference, not a schema authority; use Microsoft Learn and supplied tenant schemas as evidence. This migration workflow does not use its optional community KQL Search MCP or prior-art search.
