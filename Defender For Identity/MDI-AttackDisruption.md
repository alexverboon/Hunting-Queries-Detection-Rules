# Microsoft Defender for Identity - Attack Disruption

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |
| T1586.002 | Compromise Accounts: Email Accounts | https://attack.mitre.org/techniques/T1586/002/ |

### Description

By default, the Microsoft Defender for Identity sensor installed on a domain controller will impersonate the LocalSystem account of the domain controller and perform the attack disruption actions on the account.

Use the below query to identify Active Directory accounts disabled by a domain controller.

#### References

- [Automatic attack disruption in Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender/automatic-attack-disruption?view=o365-worldwide)
- [Remediation actions in Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/remediation-actions)
- [Automatically disrupt adversary-in-the-middle (AiTM) attacks with XDR](https://techcommunity.microsoft.com/t5/microsoft-365-defender-blog/automatically-disrupt-adversary-in-the-middle-aitm-attacks-with/ba-p/3821751)
- [[Automatically disrupt adversary-in-the-middle (AiTM) attacks with XDR])](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/)
- [How to protect against BEC & AiTM attacks via Microsoft 365 Defender | Automatic Attack Disruption](https://derkvanderwoude.medium.com/how-to-protect-against-bec-aitm-attacks-via-microsoft-365-defender-automatic-attack-disruption-13a33ca44a39)
- [How to use Automatic Attack Disruption in Microsoft 365 Defender BEC, AiTM & HumOR](https://jeffreyappel.nl/how-to-use-automatic-attack-disruption-in-microsoft-365-defender-bec-aitm-humor/)

### Microsoft Sentinel

Show disabled accounts where the actor was a domain controller - Active Directory logs

```kql
let AllDomainControllers =
        DeviceNetworkEvents
        | where TimeGenerated > ago(7d)
        | where LocalPort == 88
        | where LocalIPType == "FourToSixMapping"
        | extend DCDevicename = tostring(split(DeviceName,".")[0])
        | distinct DCDevicename;
IdentityDirectoryEvents
| where TimeGenerated > ago(190d)
| where ActionType == "Account disabled"
| extend ACTOR_DEVICE = tolower(tostring(AdditionalFields.["ACTOR.DEVICE"]))
| where isnotempty( ACTOR_DEVICE)
| where ACTOR_DEVICE in (AllDomainControllers)
| project TimeGenerated, TargetAccountDisplayName, ACTOR_DEVICE
```

When the Account is synched with Entra ID, use the following logs to see the activities in the Entra ID Audit log.

```kql
AuditLogs
| where OperationName == 'Disable account' //or OperationName == 'Update user'
| mv-expand TargetResources
| extend Actor_userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend Target_userPrincipalName = tostring(TargetResources.userPrincipalName)
| mv-apply Properties = TargetResources.modifiedProperties on ( 
project Name = Properties.displayName, AccountEnabled = (Properties.newValue)
| where Name == 'AccountEnabled'
)
| mv-apply Action =  TargetResources.modifiedProperties on ( project Name = Action.displayName, ActionClientName = Action.newValue
| where Name == 'Action Client Name')
| project TimeGenerated, OperationName,Actor_userPrincipalName, Target_userPrincipalName, AccountEnabled, ActionClientName
```
