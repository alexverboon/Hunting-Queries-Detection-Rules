# Entra ID - User Risk - On Premises Password Change

## Query Information

### Description

Use the below query to identify users that have remediated their User Risk through an On-premises Password Change

#### References

- [Remediate User Risks in Microsoft Entra ID Protection Through On-premises Password Changes](https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/remediate-user-risks-in-microsoft-entra-id-protection-through-on/ba-p/3773129)
- [What are risk detections?](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)

### Microsoft Sentinel

1. The user is at [Risk](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
2. The Users changes their password on-premises by pressing Ctrl+Alt+Delete and selecting Change password on their local Windows device that is joined to Active Directory
3. Active Directory Synch will synch the password change
4. After a while the User Risk is removed

```kql
AuditLogs
| where OperationName == "Change user password"
```

```kql
AuditLogs
| where OperationName == "Update StsRefreshTokenValidFrom Timestamp"
```

```kql
AADUserRiskEvents
| where RiskDetail == "userChangedPasswordOnPremises"
```
