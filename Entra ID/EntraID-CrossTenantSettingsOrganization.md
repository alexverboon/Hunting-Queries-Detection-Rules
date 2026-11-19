---
title: "Entra ID - Add or Delete External Tenants in Cross-Tenant Access Settings"

description: |
  Reviews Microsoft Entra audit events for additions and deletions of organization-specific cross-tenant access settings over the past 90 days. It enriches matched events with identity records from the past 30 days.

# Options: Draft | InProgress | Stable | Deprecated
status: "Draft"

# Options: Detection | ThreatHunting | ThreatIntelligence | Audit | ExposureManagement | Vulnerability
queryType: "Audit"

risk: |
  Unexpected additions or removals can change which settings apply to collaboration with an external organization. An audit event does not establish that the operation succeeded, widened access, or was unauthorized.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview"

dataSources:
  - table: "AuditLogs"
    solution: "Microsoft Entra ID / Microsoft Sentinel"
  - table: "IdentityInfo"
    solution: "Microsoft Defender XDR / Microsoft Sentinel UEBA"

version: "2.0"
created: "2026-11-19"
lastModified: "2026-11-19"
---

<!-- STATUS: uncomment the badge matching the status above -->
![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg)
<!-- ![Status: In Progress](https://img.shields.io/badge/status-in%20progress-eab308.svg) -->
<!-- ![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg) -->
<!-- ![Status: Deprecated](https://img.shields.io/badge/status-deprecated-ef4444.svg) -->

<!-- QUERY TYPE: uncomment the badge matching the queryType above -->
<!-- ![Type: Detection](https://img.shields.io/badge/type-detection-ef4444.svg) -->
<!-- ![Type: Threat Hunting](https://img.shields.io/badge/type-threat%20hunting-f97316.svg) -->
<!-- ![Type: Threat Intelligence](https://img.shields.io/badge/type-threat%20intelligence-a855f7.svg) -->
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
<!-- ![Type: Exposure Management](https://img.shields.io/badge/type-exposure%20management-8b5cf6.svg) -->
<!-- ![Type: Vulnerability](https://img.shields.io/badge/type-vulnerability-eab308.svg) -->

![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Entra ID - Add or Delete External Tenants in Cross-Tenant Access Settings

## Query Information

### Description

Reviews two Microsoft Entra audit operations: adding a partner to cross-tenant access settings and deleting partner-specific settings. It looks back 90 days for audit events, extracts the target tenant ID, initiating user UPN, and IP address where present, and estimates the country from the IP address. A left join adds any matching display name, company, and department from the past 30 days of identity records.

### Risk

Unexpected additions or removals can change which settings apply to collaboration with an external organization. An audit event does not establish that the operation succeeded, widened access, or was unauthorized. Check the original event outcome and compare the resulting settings with the approved change.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [Microsoft Entra cross-tenant access overview](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview)


### Data Sources

| Table | Solution |
| --- | --- |
| `AuditLogs` | Microsoft Entra ID / Microsoft Sentinel |
| `IdentityInfo` | Microsoft Defender XDR / Microsoft Sentinel UEBA |

---

## KQL Query

```kql

let identities = (
IdentityInfo
| where TimeGenerated > ago(30d)
| where isnotempty( AccountUpn)
| distinct AccountUpn, AccountDisplayName, CompanyName, Department);
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == "Delete partner specific cross-tenant access setting" or OperationName == "Add a partner to cross-tenant access setting"
| extend userPrincipalName = tostring(parse\_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TenantID = tostring(parse\_json(tostring(parse\_json(tostring(TargetResources\[0].modifiedProperties))\[0].newValue)))
| extend ipAddress = tostring(parse\_json(tostring(InitiatedBy.user)).ipAddress)
| extend IpAddressLocation = geo\_info\_from\_ip\_address(ipAddress)
| extend Country = tostring(IpAddressLocation.country)
| project TimeGenerated,OperationName, TenantID, userPrincipalName, ipAddress, Country
| join kind=leftouter (identities)
on $left. userPrincipalName == $right. AccountUpn
| sort by TimeGenerated asc 
```





