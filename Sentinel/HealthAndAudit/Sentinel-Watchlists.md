---
title: "Microsoft Sentinel Watchlist Inventory"

description: |
  This query provides a Microsoft Sentinel Watchlist inventory. It summarizes the watchlist name,
  last updated timestamp, and number of entries in each watchlist. It also resolves the creator
  and updater object IDs to available user, managed identity, or service principal names.

status: "Stable"

queryType: "Audit"

risk: |
  Unexpected watchlists or changes to watchlist ownership and contents may indicate
  misconfiguration or unauthorized configuration activity. Results identify inventory
  and governance context but do not by themselves prove malicious activity.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/watchlist"
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/identityinfo"
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs"
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs"
  - "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs"

mitre: []

dataSources:
  - table: "Watchlist"
    solution: "Microsoft Sentinel"
  - table: "IdentityInfo"
    solution: "Microsoft Sentinel UEBA"
  - table: "SigninLogs"
    solution: "Microsoft Entra ID"
  - table: "AADManagedIdentitySignInLogs"
    solution: "Microsoft Entra ID"
  - table: "AADServicePrincipalSignInLogs"
    solution: "Microsoft Entra ID"

version: "2.0"
created: "2026-11-24"
lastModified: "2026-11-24"
---

![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg)
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Microsoft Sentinel Watchlist Inventory

## Query Information

### Description

This query provides a Microsoft Sentinel Watchlist inventory. It summarizes the watchlist name,
last updated timestamp, and number of entries in each watchlist. It also resolves the creator
and updater object IDs to available user, managed identity, or service principal names.

### Risk

Unexpected watchlists or changes to watchlist ownership and contents may indicate
misconfiguration or unauthorized configuration activity. This audit query provides
inventory and governance context; a result alone does not prove malicious activity.

### Author

- **Name:** Alex Verboon
- **Link:** [https://github.com/alexverboon](https://github.com/alexverboon)

### References

- [Watchlist table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/watchlist)
- [IdentityInfo table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/identityinfo)
- [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [AADManagedIdentitySignInLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs)
- [AADServicePrincipalSignInLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)

### Data Sources

| Table | Solution |
| --- | --- |
| `Watchlist` | Microsoft Sentinel |
| `IdentityInfo` | Microsoft Sentinel UEBA |
| `SigninLogs` | Microsoft Entra ID |
| `AADManagedIdentitySignInLogs` | Microsoft Entra ID |
| `AADServicePrincipalSignInLogs` | Microsoft Entra ID |

### False Positives and Tuning

Expected matches include intentionally created or updated watchlists and routine ownership
changes. Tune the TimeGenerated lookback or project additional watchlist fields as needed
for your tenant's inventory and governance process.

### Investigation Guidance

Review the watchlist category, source, and contents for unexpected additions or changes.
Correlate creator and updater identities with change tickets and relevant sign-in activity.
For unresolved object IDs, verify that the relevant identity and sign-in tables are enabled
and that identity enrichment is available in the workspace.

---

## KQL Query

```kql
let IdentityLookup = materialize(
    union isfuzzy=true
        (IdentityInfo
        | project TimeGenerated,
            ObjectId = AccountObjectId,
            ResolvedName = AccountUPN,
            IdentityType = "User"),
        (SigninLogs
        | project TimeGenerated,
            ObjectId = UserId,
            ResolvedName = UserPrincipalName,
            IdentityType = "User"),
        (AADManagedIdentitySignInLogs
        | project TimeGenerated,
            ObjectId = ServicePrincipalId,
            ResolvedName = ServicePrincipalName,
            IdentityType = "Managed Identity"),
        (AADServicePrincipalSignInLogs
        | project TimeGenerated,
            ObjectId = ServicePrincipalId,
            ResolvedName = ServicePrincipalName,
            IdentityType = "Service Principal")
    | where TimeGenerated > ago(90d)
    | where isnotempty(ObjectId) and isnotempty(ResolvedName)
    | extend ObjectId = tolower(ObjectId)
    | summarize arg_max(TimeGenerated, *) by ObjectId
    | project ObjectId, ResolvedName, IdentityType
);
Watchlist
| where TimeGenerated > ago(720d)
| summarize
    ListCount = dcount(WatchlistItemId)-1,
    arg_max(TimeGenerated, *)
    by WatchlistAlias
| extend
    Created_name = tostring(CreatedBy.name),
    Created_objectId = tolower(tostring(CreatedBy.objectId)),
    Updated_name = tostring(UpdatedBy.name),
    Updated_objectId = tolower(tostring(UpdatedBy.objectId))
| lookup kind=leftouter (
    IdentityLookup
    | project
        Created_objectId = ObjectId,
        Created_ResolvedName = ResolvedName,
        Created_IdentityType = IdentityType
    ) on Created_objectId
| lookup kind=leftouter (
    IdentityLookup
    | project
        Updated_objectId = ObjectId,
        Updated_ResolvedName = ResolvedName,
        Updated_IdentityType = IdentityType
    ) on Updated_objectId
| extend
    Created_name = coalesce(Created_ResolvedName, Created_name),
    Updated_name = coalesce(Updated_ResolvedName, Updated_name),
    Created_IdentityType = coalesce(Created_IdentityType, "Unknown"),
    Updated_IdentityType = coalesce(Updated_IdentityType, "Unknown")
| project
    WatchlistId,
    WatchlistAlias,
    WatchlistName,
    CreatedTimeUTC,
    LastUpdatedTimeUTC,
    ListCount,
    Created_name,
    Created_IdentityType,
    Created_objectId,
    Updated_name,
    Updated_IdentityType,
    Updated_objectId
| order by WatchlistAlias asc
```
