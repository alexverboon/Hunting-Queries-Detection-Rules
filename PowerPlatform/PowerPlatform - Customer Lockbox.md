# Power Platform - Customer Lockbox

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### Description

This query retrieves events for enabling or disabling Power Platform Customer Lockbox.

#### References

- [Securely access customer data by using Customer Lockbox in Power Platform and Dynamics 365](https://learn.microsoft.com/en-us/power-platform/admin/about-lockbox)

### Author

- **Alex Verboon**

## Defender XDR

```kql
PowerPlatformAdminActivity
| where EventOriginalType == "TenantLockboxOperation"
| where EventResult == "Succeeded"
| where Properties.["powerplatform.analytics.activity.name"] == "TenantLockboxOperation"
| extend LockBoxEnabled = tostring(Properties.["powerplatform.analytics.resource.tenant.is_lockbox_enabled"])
| project TimeGenerated, ActorName, ActorUserId, LockBoxEnabled
```

```kql
CloudAppEvents
| where ActionType == "TenantLockboxOperation"
| where parse_json(tostring(RawEventData.JsonPropertiesCollection)).["powerplatform.analytics.activity.name"] == "TenantLockboxOperation"
| extend LockBoxEnabled = tostring(parse_json(tostring(RawEventData.JsonPropertiesCollection)).["powerplatform.analytics.resource.tenant.is_lockbox_enabled"])
| project TimeGenerated, AccountDisplayName, LockBoxEnabled
```


