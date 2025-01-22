# Entra ID - Suspicious activity reported

## Query Information

### Description

This KQL query identifies events where users report MFA prompts as suspicious, triggering a "High User Risk" classification within Microsoft Entra ID Protection. It provides visibility into potential fraud attempts.

#### References

- [Retirement - MFA Fraud Alert will be retired on March 1st 2025](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new#retirement---mfa-fraud-alert-will-be-retired-on-march-1st-2025)
- [Report suspicious activity](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#report-suspicious-activity)

### Microsoft Sentinel

```kql
AuditLogs
| where OperationName == "Suspicious activity reported"
| extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
```
