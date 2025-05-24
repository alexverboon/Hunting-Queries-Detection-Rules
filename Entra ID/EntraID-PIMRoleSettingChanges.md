# EntraID - Privileged Identity Management - Role Settings Changes

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.003 | Account Manipulation: Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003/ |

### Description

Use the below query to retrieve EntraID - Privileged Identity Management - Role & Group Settings Changes

MFA on activation requirement (enabled/disabled)
Ticket info requirement (enabled/disabled)
Approval (enabled/disabled)
Approval enabled with approvers
Approver settings - Default recipients settings disabled
Maximum active assignment duration set to (Days)
Maximum eligible assignment duration set to (Days)
MFA on active assignment requirement (enabled/disabled)
Notification updates in eligible members activate the role - Admin settings - Default recipients settings (enabled/disabled)
Notification updates in members are assigned as active to the role - Admin settings - Default recipients settings (enabled/disabled)
Notification updates in members are assigned as eligible to the role - Admin settings - Default recipients settings (enabled/disabled)
Notification updates in members are assigned as eligible to the role - Admin settings - Default recipients settings (enabled/disabled)
Permanently active assignments (enabled/disabled)
Permanently eligible assignments (enableddisabled)
Requestor settings - Default recipients settings (enabled/disabled)

#### References

- [Microsoft Entra Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [Entra PIM Roles & Groups Settings Changes - Dashbaord](https://github.com/alexverboon/Entra-PIM-Helpers/blob/630959be8918d7b646e1e958f3d21be446e0c133/Workbook/EntraPIMChanges.json)

### Microsoft Sentinel

```kql
AuditLogs
| where Category == "RoleManagement" or Category == "GroupManagement"
| where OperationName == "Update role setting in PIM"
| extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend Role = case(
    Category == 'RoleManagement',tostring(TargetResources[0].displayName),
    "")
| extend Group = case(
    Category  == "GroupManagement", tostring(TargetResources[2].displayName),
    "")
| mv-apply item = AdditionalDetails on (
    where tostring(item.key) == "ipaddr"
    | extend ipaddr = tostring(item.value)
    )
| mv-apply item = AdditionalDetails on (
    where tostring(item.key) == "UserAgent"
    | extend UserAgent = tostring(item.value)
    )
| extend geo_ip = tostring(geo_info_from_ip_address(ipaddr))
| sort by TimeGenerated asc 
| sort by TimeGenerated asc 
| extend ChangedSettings = replace("Setting changes in this session: ", "", tostring(ResultReason))
| extend ModifiedSettings = extract_all(@"(.*?)\.", ChangedSettings)
| project-away ChangedSettings
| project
    TimeGenerated,
    Role,
    Group,
    ResultReason,
    ModifiedSettings,
    userPrincipalName,
    Identity,
    ipaddr,
    UserAgent,
    geo_ip,
    CorrelationId
```

Only list events where ***MFA on activation requirement*** was changed

```kql
AuditLogs
| where Category == "RoleManagement" or Category == "GroupManagement"
| where OperationName == "Update role setting in PIM"
| extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
//| extend Role = tostring(TargetResources[0].displayName)
| extend Role = case(
    Category == 'RoleManagement',tostring(TargetResources[0].displayName),
    "")
| extend Group = case(
    Category  == "GroupManagement", tostring(TargetResources[2].displayName),
    "")
| mv-apply item = AdditionalDetails on (
    where tostring(item.key) == "ipaddr"
    | extend ipaddr = tostring(item.value)
    )
| mv-apply item = AdditionalDetails on (
    where tostring(item.key) == "UserAgent"
    | extend UserAgent = tostring(item.value)
    )
| extend geo_ip = tostring(geo_info_from_ip_address(ipaddr))
| sort by TimeGenerated asc 
| sort by TimeGenerated asc 
| extend ChangedSettings = replace("Setting changes in this session: ", "", tostring(ResultReason))
| extend ModifiedSettings = extract_all(@"(.*?)\.", ChangedSettings)
| project-away ChangedSettings
| project
    TimeGenerated,
    Role,
    Group,
    ResultReason,
    ModifiedSettings,
    userPrincipalName,
    Identity,
    ipaddr,
    UserAgent,
    geo_ip,
    CorrelationId
    | where ModifiedSettings has_any ("MFA on activation requirement")
    ```
