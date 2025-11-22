# Entra ID - Oauth App Information

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Released](https://img.shields.io/badge/status-released-brightgreen.svg)

## Query Information

### Description

Use the below info to query to OAuthAppInfo table in Defender XDR

### Author

- Alex Verboon

#### References

- [OAuthAppInfo (Preview)](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-oauthappinfo-table)

### Microsoft Defender XDR

List relevant information from the OAutahAppInfo Table and count the permissions by Permission Level

```kql
OAuthAppInfo 
| summarize arg_max(TimeGenerated,*) by OAuthAppId
| mv-expand Permissions
| extend Permission = tostring(parse_json(Permissions.PermissionValue))
| extend PermPrivilegeLevel = tostring(parse_json(Permissions.PrivilegeLevel))
| project
    AppName,
    PrivilegeLevel,
    Permission,
    AppStatus,
    ConsentedUsersCount,
    IsAdminConsented,
    AppOrigin,
    ServicePrincipalId,
    Permissions,
    PermPrivilegeLevel
| summarize
    //PrivLevels = make_set(PermPrivilegeLevel),
    Low = countif(PermPrivilegeLevel == "Low"),
    Medium = countif(PermPrivilegeLevel == "Medium"),
    High = countif(PermPrivilegeLevel == "High"),
    NA = countif(PermPrivilegeLevel == "NA")
    by AppName, ConsentedUsersCount, IsAdminConsented, AppStatus, AppOrigin
| order by High desc, Medium desc, Low desc

```

External OAuth Apps and their external Tenant ID information

```kql
OAuthAppInfo
| where isnotempty( AppOwnerTenantId)
| where AppOrigin == 'External'
| summarize arg_max(TimeGenerated,*) by OAuthAppId
| project AppName, VerifiedPublisher, ServicePrincipalId, OAuthAppId, PrivilegeLevel, Permissions, AppOrigin, AppOwnerTenantId
| extend VerifiedPublisher_displayName = tostring(parse_json(VerifiedPublisher)["displayName"])
```