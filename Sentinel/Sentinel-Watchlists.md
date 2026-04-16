# Sentinel - Watchlist

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)

![Status: In Progress](https://img.shields.io/badge/status-in--progress-yellow.svg)

## Query Information

### Description

DESCRIPTION

#### References

### Author

- **Alex Verboon**

## Sentinel

```kql
Watchlist
| where TimeGenerated > ago(720d)
| summarize
    ListCount          = dcount(WatchlistItemId)-1,
    WatchlistId        = any(WatchlistId),
    any_CreatedTimeUTC = any(CreatedTimeUTC),
    any_UpdatedTimeUTC = any(LastUpdatedTimeUTC),
    any_CreatedBy      = any(CreatedBy),
    any_UpdatedBy      = any(UpdatedBy), 
    any_WatchListAlias = any(WatchlistAlias),
    any_WatchlistName = any(WatchlistName)
  by WatchlistAlias
| extend
    WatchListAlias = any_WatchListAlias,
    WatchlistName = any_WatchlistName,
    CreatedTimeUTC     = any_CreatedTimeUTC,
    LastUpdatedTimeUTC = any_UpdatedTimeUTC,
    Created_name       = tostring(any_CreatedBy.name),
    Created_objectId   = tostring(any_CreatedBy.objectId),
    Updated_name       = tostring(any_UpdatedBy.name),
    Updated_objectId   = tostring(any_UpdatedBy.objectId)
| project
    WatchlistId,
    WatchListAlias,
    WatchlistName,
    CreatedTimeUTC,
    LastUpdatedTimeUTC,
    ListCount,
    Created_name,
    Created_objectId,
    Updated_name,
    Updated_objectId
| order by WatchListAlias asc
```
