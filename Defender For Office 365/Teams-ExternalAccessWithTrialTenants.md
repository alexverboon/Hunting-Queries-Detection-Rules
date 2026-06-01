# Teams - ExternalAccessWithTrialTenants

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### Description

This query tracks Microsoft Teams admin configuration changes to the `ExternalAccessWithTrialTenants` federation setting. It helps detect when external communication with Teams trial-only tenants (tenants with no purchased licenses) is changed between `Blocked` and `Allowed`, which can directly impact whether users can find, chat, call, and meet with users from those tenants. From a risk perspective, changing this setting to `Allowed` increases exposure to external communication from less-established trial tenants, which can raise the likelihood of spam, social engineering, and unauthorized external contact. Attackers have abused trial tenants in past campaigns, so monitoring this setting helps identify potentially risky changes early.


#### References

- [Block federation with Teams trial-only tenants](https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings#block-federation-with-teams-trial-only-tenants)
- [Teams to Block Federated Communications with Trial Tenants](https://office365itpros.com/2024/06/27/federated-communications-block/?utm_source=chatgpt.com)


### Author

- **Alex Verboon**

## Defender XDR

```kql
CloudAppEvents
| where ActionType == "TeamsAdminAction"
| where RawEventData has "ExternalAccessWithTrialTenants"
| extend ModifiedProperties = parse_json(RawEventData).ModifiedProperties
| mv-apply ModifiedProperties on
(
    where ModifiedProperties.Name == "ExternalAccessWithTrialTenants"
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


