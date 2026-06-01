# Microsoft Defender for Office 365 - Tenant Allow/Block List changes.

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### Description

This query identifies recent Tenant Allow/Block List add, update, and removal actions in Microsoft Defender for Office 365, and surfaces the actor, action type, and key entry details (such as list type, block state, notes, and expiration).

#### References

- [Manage allows and blocks in the Tenant Allow/Block List](https://learn.microsoft.com/en-us/defender-office-365/tenant-allow-block-list-about)

### Author

- **Alex Verboon**

## Defender XDR

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any (
    "New-TenantAllowBlockListItems",
    "Remove-TenantAllowBlockListItems",
    "Set-TenantAllowBlockListItems"
)
| extend Data = parse_json(RawEventData)
| extend Parameters = Data.Parameters
| mv-expand Parameters
| extend 
    Name = tostring(Parameters.Name),
    Value = tostring(Parameters.Value)
| summarize 
    Details = make_bag(pack(Name, Value))
    by Timestamp, ActionType, AccountDisplayName
| evaluate bag_unpack(Details)
| project
    Timestamp,
    ActionType,
    AccountDisplayName,
    Entries,
    ListType,
    Block,
    Notes,
    ExpirationDate
| order by Timestamp desc
```


