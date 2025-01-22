# Entra ID - Self Serfice Password Reset - Configuration Changes

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                          | Reference Link                                                  |
|--------------|--------------------------------|------------------------------------------------------------------|
| T1098        | Account Manipulation          | [T1098](https://attack.mitre.org/techniques/T1098/) |
| T1556        | Modify Authentication Process | [T1556](https://attack.mitre.org/techniques/T1556/) |

### Description

Microsoft has introduced enhanced logging capabilities for Self-Service Password Reset (SSPR) policy configurations. With this update, any change made to the SSPR policy configuration—including enablement, disablement, or modifications—will generate an audit log entry detailing the change.

The audit log entry includes the following details:

- Change Details: A description of the action taken (e.g., enabled or disabled the policy).
- Previous and Current Values: Both the prior and updated configuration settings are recorded, providing comprehensive insight into the nature of the change.

To assist with detecting and analyzing these changes, the below KQL (Kusto Query Language) query can be used:

#### Risk

#### Author

- **Name:Alex Verboon**

#### References

- [General Availability - Expansion of SSPR Policy Audit Logging](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new#general-availability---expansion-of-sspr-policy-audit-logging)
- [Self-service password management](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#self-service-password-management)

### Microsoft Sentinel

```kql
AuditLogs
| where OperationName == "Update SSPR Settings"
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
|mv-expand parse_json(TargetResources)[0].modifiedProperties
| extend SSPR_Setting = tostring(TargetResources_0_modifiedProperties.displayName)
| extend newValue = tostring(parse_json(tostring(TargetResources_0_modifiedProperties.newValue)))
| extend oldValue = tostring(parse_json(tostring(TargetResources_0_modifiedProperties.oldValue)))
| project TimeGenerated, SSPR_Setting, oldValue, newValue, Actor, CorrelationId
```
