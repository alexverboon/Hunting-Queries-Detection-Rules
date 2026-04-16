# Entra ID - Add or Delete external Tenant to Cross Tenant Settings.

## Query Information

### Description

DESCRIPTION

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
let identities = (
IdentityInfo
| where TimeGenerated > ago(30d)
| where isnotempty( AccountUpn)
| distinct AccountUpn, AccountDisplayName, CompanyName, Department);
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == "Delete partner specific cross-tenant access setting" or OperationName == "Add a partner to cross-tenant access setting"
| extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TenantID = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)))
| extend ipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend IpAddressLocation = geo_info_from_ip_address(ipAddress)
| extend Country = tostring(IpAddressLocation.country)
| project TimeGenerated,OperationName, TenantID, userPrincipalName, ipAddress, Country
| join kind=leftouter (identities)
on $left. userPrincipalName == $right. AccountUpn
| sort by TimeGenerated asc 
```


