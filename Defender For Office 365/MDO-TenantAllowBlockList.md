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
| mv-expand Parameter = Data.Parameters
| extend 
    ParamName = tostring(Parameter.Name),
    ParamValue = tostring(Parameter.Value)
| summarize 
    Entries = take_anyif(ParamValue, ParamName == "Entries"),
    ListType = take_anyif(ParamValue, ParamName == "ListType"),
    Block = take_anyif(ParamValue, ParamName == "Block"),
    Notes = take_anyif(ParamValue, ParamName == "Notes"),
    ExpirationDate = take_anyif(ParamValue, ParamName == "ExpirationDate")
    by Timestamp, ActionType, AccountDisplayName
| order by Timestamp desc
```


