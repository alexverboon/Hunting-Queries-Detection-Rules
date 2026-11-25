---
title: "Defender XDR Alert Tuning Rule Changes"

description: |
  Audits changes to Defender XDR alert tuning rules to help identify and review
  changes that could affect alert visibility.

status: "Stable"
queryType: "Audit"

risk: |
  Unauthorized or inappropriate rule changes could suppress relevant alerts.
  A matching operation is not, by itself, evidence of malicious activity.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table"
  - "https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender"

mitre: []

dataSources:
  - table: "CloudAppEvents"
    solution: "Microsoft Defender for Cloud Apps / Microsoft Defender XDR"

version: "1.0"
created: "2026-11-25"
lastModified: "2026-11-25"
---

![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg)
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Defender XDR Alert Tuning Rule Changes

## Query Information

### Description

Audits changes to Defender XDR alert tuning rules to help identify and review
changes that could affect alert visibility.

### Risk

Unauthorized or inappropriate rule changes could suppress relevant alerts.
Changes can also be legitimate; review their context before drawing conclusions.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [CloudAppEvents advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table)
- [Stream Defender XDR data to Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender)

### MITRE ATT&CK Technique(s)

None: the audited operations alone do not establish adversary behavior.

### Data Sources

| Table | Solution |
| --- | --- |
| `CloudAppEvents` | Microsoft Defender for Cloud Apps / Microsoft Defender XDR |

### Investigation Guidance

Review the actor, operation, rule scope and conditions, and confirm whether the
change was authorized and appropriate.

---

## KQL Query

```kql
CloudAppEvents
| where ActionType in (
    "CreateSuppressionRule",
    "DeleteSuppressionRule",
    "DisableSuppressionRule",
    "EditSuppressionRule",
    "EnableSuppressionRule"
)
| extend RuleOperation = case(
    ActionType == "CreateSuppressionRule",  "Created",
    ActionType == "DeleteSuppressionRule",  "Deleted",
    ActionType == "DisableSuppressionRule", "Disabled",
    ActionType == "EditSuppressionRule",    "Modified",
    ActionType == "EnableSuppressionRule",  "Enabled",
    "Unknown"
)
| extend
    RuleId = tostring(RawEventData.SuppressionRuleId),
    RuleTitle = tostring(RawEventData.RuleTitle),
    RuleAction = tostring(RawEventData.Action),
    RuleIsEnabled = tobool(RawEventData.IsEnabled),
    IoaDefinitionId = tostring(RawEventData.IoaDefinitionId),
    RuleConditions = parse_json(tostring(RawEventData.RuleConditions)),
    ScopeConditions = parse_json(tostring(RawEventData.ScopeConditions)),
    UserId = tostring(RawEventData.UserId),
    UserKey = tostring(RawEventData.UserKey),
    UserType = toint(RawEventData.UserType),
    OrganizationId = tostring(RawEventData.OrganizationId),
    AuditEventId = tostring(RawEventData.Id),
    AuditOperation = tostring(RawEventData.Operation),
    AuditCreationTime = todatetime(RawEventData.CreationTime),
    ClientIP = tostring(RawEventData.ClientIP),
    RecordType = toint(RawEventData.RecordType),
    Workload = tostring(RawEventData.Workload)
| extend
    ConditionType = tostring(RuleConditions.conditionType),
    LogicalOperator = tostring(RuleConditions.logicalOperator)
| extend ConditionArray = case(
    ConditionType == "Simple", pack_array(RuleConditions),
    ConditionType == "Complex", RuleConditions.conditions,
    dynamic([])
)
| extend ConditionCount = coalesce(array_length(ConditionArray), 0)
| extend ConditionArray = iff(
    ConditionCount == 0,
    dynamic([null]),
    ConditionArray
)
| mv-apply Condition = ConditionArray on (
    extend
        EntityRole = tostring(Condition.entityRole),
        IocDisplayName = tostring(Condition.iocDisplayName),
        IocType = tostring(Condition.iocType),
        PredicateOperator = tostring(Condition.predicate.operator),
        PredicateValue = tostring(Condition.predicate.value),
        PredicateValueType = tostring(Condition.predicate.valueType),
        PredicateType = tostring(Condition.predicate.predicateType)
    | summarize
        EntityRoles = make_set_if(EntityRole, isnotempty(EntityRole)),
        IocDisplayNames = make_set_if(IocDisplayName, isnotempty(IocDisplayName)),
        IocTypes = make_set_if(IocType, isnotempty(IocType)),
        PredicateOperators = make_set_if(PredicateOperator, isnotempty(PredicateOperator)),
        PredicateValues = make_set_if(PredicateValue, isnotempty(PredicateValue)),
        PredicateValueTypes = make_set_if(PredicateValueType, isnotempty(PredicateValueType)),
        PredicateTypes = make_set_if(PredicateType, isnotempty(PredicateType)),
        ConditionDetails = make_list_if(
            bag_pack(
                "EntityRole", EntityRole,
                "IocDisplayName", IocDisplayName,
                "IocType", IocType,
                "Operator", PredicateOperator,
                "Value", PredicateValue,
                "ValueType", PredicateValueType,
                "PredicateType", PredicateType
            ),
            isnotempty(PredicateType)
        )
)
| project
    TimeGenerated,
    RuleOperation,
    RuleId,
    RuleTitle,
    RuleAction,
    RuleIsEnabled,
    IoaDefinitionId,
    ConditionType,
    ConditionCount,
    LogicalOperator,
    EntityRoles,
    IocDisplayNames,
    IocTypes,
    PredicateOperators,
    PredicateValues,
    PredicateValueTypes,
    PredicateTypes,
    ConditionDetails,
    RuleConditions,
    ScopeConditions,
    AccountDisplayName,
    AccountObjectId,
    AccountType,
    UserId,
    UserKey,
    UserType,
    IPAddress,
    ClientIP,
    IsAdminOperation,
    IsExternalUser,
    AuditEventId,
    AuditOperation,
    AuditCreationTime
| order by TimeGenerated desc
// Defender XDR Alert Tuning Rules
```
