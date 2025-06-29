# Entra ID - Oauth App Information

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
| mv-expand Permissions
| extend Permission = tostring(parse_json(Permissions.PermissionValue))
| project
    AppName,
    PrivilegeLevel,
    Permission,
    AppStatus,
    ConsentedUsersCount,
    IsAdminConsented,
    AppOrigin
| summarize
    Permissions = make_set(Permission),
    Low = countif(PrivilegeLevel == "Low"),
    Medium = countif(PrivilegeLevel == "Medium"),
    High = countif(PrivilegeLevel == "High")
    by AppName, ConsentedUsersCount, IsAdminConsented, AppStatus, AppOrigin
| order by High desc, Medium desc, Low desc

```
