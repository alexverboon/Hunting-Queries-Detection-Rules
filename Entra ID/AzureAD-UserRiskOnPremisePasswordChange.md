# Entra ID - User Risk - On Premises Password Change

## Query Information

### Description

Hybrid users can complete a password change by pressing Ctrl+Alt+Del and changing their password from an on-premises or hybrid joined Windows device, when password hash synchronization and the **Allow on-premises password change to reset user risk** setting is enabled.

Use the below query to identify users that have remediated their User Risk through an On-premises Password Change

#### References

- [Remediate User Risks in Microsoft Entra ID Protection Through On-premises Password Changes](https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/remediate-user-risks-in-microsoft-entra-id-protection-through-on/ba-p/3773129)
- [Remediate risks and unblock users](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock)
- [What are risk detections?](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)

### Microsoft Sentinel

1. The user is at [Risk](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
2. The Users changes their password on-premises by pressing Ctrl+Alt+Delete and selecting Change password on their local Windows device that is joined to Active Directory
3. Azure AD Connect will synch the password change
4. The User Risk is removed

```kql
AuditLogs
| where OperationName == "Change user password"
```

```kql
AuditLogs
| where OperationName == "Update StsRefreshTokenValidFrom Timestamp"
```

When **Allow on-premises password change to reset user risk** setting is enabled, you get the following event

```kql
AADUserRiskEvents
| where RiskDetail == "userChangedPasswordOnPremises"
```
