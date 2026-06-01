# Teams - Allowed Domains

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### Description

This query identifies Microsoft Teams admin changes to the `AllowedDomains` external access setting. It helps track when trusted Microsoft 365 domains are added, removed, or modified, which affects which external organizations your users are permitted to chat and meet with.

#### References

- [Teams - Specify trusted Microsoft 365 organizations](https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings#specify-trusted-microsoft-365-organizations)

### Author

- **Alex Verboon**

## Defender XDR

```kql
CloudAppEvents
| where ActionType == "TeamsAdminAction"
| where RawEventData has "AllowedDomains"
| extend ModifiedProperties = parse_json(RawEventData).ModifiedProperties
| mv-apply ModifiedProperties on
(
    where ModifiedProperties.Name == "AllowedDomains"
    | project 
        PropertyName = tostring(ModifiedProperties.Name),
        NewValue = tostring(ModifiedProperties.NewValue),
        OldValue = tostring(ModifiedProperties.OldValue)
)
| project 
    TimeGenerated,
    ActionType,
    AccountDisplayName,
    PropertyName,
    OldValue,
    NewValue,
    RawEventData
```


