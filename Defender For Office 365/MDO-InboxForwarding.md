# Exchange Online - Email Inbox Manipulation & Forwarding

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1114.003 | Email Collection: Email Forwarding Rule  | https://attack.mitre.org/techniques/T1114/003/ |

### Description

Use the below queries to detect and investigate suspicious email inbox manipulation and forwarding activities

#### References

- [Alert classification for suspicious inbox manipulation rules](https://learn.microsoft.com/en-us/microsoft-365/security/defender/alert-grading-playbook-inbox-manipulation-rules?view=o365-worldwide)
- [Alert classification for suspicious inbox forwarding rules](https://learn.microsoft.com/en-us/microsoft-365/security/defender/alert-grading-playbook-inbox-forwarding-rules?view=o365-worldwide)
- [Alert classification for suspicious email forwarding activity](https://learn.microsoft.com/en-us/microsoft-365/security/defender/alert-grading-playbook-email-forwarding?view=o365-worldwide)
- [Control automatic external email forwarding in Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding?view=o365-worldwide)
- [Behind the scenes of business email compromise: Using cross-domain threat data to disrupt a large BEC campaign](https://www.microsoft.com/en-us/security/blog/2021/06/14/behind-the-scenes-of-business-email-compromise-using-cross-domain-threat-data-to-disrupt-a-large-bec-infrastructure/)
- [Configure outbound spam policies in EOP](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-configure?view=o365-worldwide)
- [Detecting suspicious email forwarding rules on Office 365](https://redcanary.com/blog/email-forwarding-rules/)
- [Microsoft Clamps Down on Automatic Mail Forwarding in Exchange Online](https://office365itpros.com/2020/11/12/forwarding-email-exchange-online/)

### Microsoft Defender XDR

Use the below queries to identify changes to the Exchange Online - Anti-spam outbound policy

```kql
OfficeActivity
| where Operation == "Set-HostedOutboundSpamFilterPolicy"
| mv-expand parse_json(Parameters)
| where Parameters.Name == "AutoForwardingMode"
| extend Mode = tostring(Parameters.Value)
```

```kql
CloudAppEvents
| where ObjectName == "Set-HostedOutboundSpamFilterPolicy"
| mv-expand parse_json(ActivityObjects)
| where ActivityObjects.Name == 'AutoForwardingMode'
| extend Mode = tostring(ActivityObjects.Value)
| project TimeGenerated, Mode, AccountId, AccountType, AccountObjectId, AccountDisplayName,ISP, City, CountryCode, IPAddress, IPTags, Application
```

***Additional Information***

- Account Type: *Application* when the change is done within the Admin portal, *Admin* when executed for example via Azure Cloud Shell
- ISP: Microsoft Azure, Exchange Online Server
- AccountID = 00000007-0000-0ff1-ce00-000000000000 Microsoft.ExchangeOnlineProtection when configured thorugh the Admin Portal or the users Entra ObjectID when executed via PowerShell
- AccountDisplayName:  - Microsoft Exchange Online Protection when configured through the Portal or the Users DisplayName when executed via PowerShell
- AccountObjectID: Only populated when executed by an Admin via PowerShell (not via the Admin Portal)

Find signins to Exchange Online with PowerShell.

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where AppDisplayName == "Microsoft Exchange REST API Based Powershell"
```

***PowerShell***
PowerShell command to configure AutoForwardingMode in the outbound spam filter policy

```powershell
set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode <Automatic|On|Off|>
```

**Advanced Hunting**
***Below queries are from the above referenced Microsoft articiles***

Use this query to find all the new inbox rule events during specific time window.

```kql
let start_date = now(-10h);
let end_date = now();
let user_id = ""; // enter here the user id
CloudAppEvents
| where Timestamp between (start_date .. end_date)
| where AccountObjectId == user_id
| where Application == @"Microsoft Exchange Online"
| where ActionType in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule", "UpdateInboxRules") //set new inbox rule related operations
| project Timestamp, ActionType, CountryCode, City, ISP, IPAddress, RuleConfig = RawEventData.Parameters, RawEventData
```

Use this query to check whether the ISP is common for the user by looking at the history of the user.

```kql
let alert_date = now(); //enter alert date
let timeback = 60d;
let userid = ""; //enter here user id
CloudAppEvents
| where Timestamp between ((alert_date-timeback)..(alert_date-1h))
| where AccountObjectId == userid
| make-series ActivityCount = count() default = 0 on Timestamp  from (alert_date-timeback) to (alert_date-1h) step 12h by ISP
```

Use this query to check whether the country/region is common for the user by looking at the history of the user.

```kql
let alert_date = now(); //enter alert date
let timeback = 60d;
let userid = ""; //enter here user id
CloudAppEvents
| where Timestamp between ((alert_date-timeback)..(alert_date-1h))
| where AccountObjectId == userid
| make-series ActivityCount = count() default = 0 on Timestamp  from (alert_date-timeback) to (alert_date-1h) step 12h by CountryCode
```

Use this query to check whether the user agent is common for the user by looking at the history of the user.

```kql
let alert_date = now(); //enter alert date
let timeback = 60d;
let userid = ""; //enter here user id
CloudAppEvents
| where Timestamp between ((alert_date-timeback)..(alert_date-1h))
| where AccountObjectId == userid
| make-series ActivityCount = count() default = 0 on Timestamp  from (alert_date-timeback) to (alert_date-1h) step 12h by UserAgent
```

Run this query to check if other users created forward rule to the same destination (could indicate that other users are compromised as well).

```kql
let start_date = now(-10h);
let end_date = now();
let dest_email = ""; // enter here destination email as seen in the alert
CloudAppEvents
| where Timestamp between (start_date .. end_date)
| where ActionType in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule") //set new inbox rule related operations
| project Timestamp, ActionType, CountryCode, City, ISP, IPAddress, RuleConfig = RawEventData.Parameters, RawEventData
| where RuleConfig has dest_email
```

SRL/RL: Use the (Suspicious) Recipients List in Threat Explorer
Run this query to find out who else has forwarded emails to these recipients (SRL/RL).

```kql
let srl=pack_array("{SRL}"); //Put values from SRL here.
EmailEvents
| where RecipientEmailAddress in (srl)
| distinct SenderDisplayName, SenderFromAddress, SenderObjectId
```

Run this query to find out how many emails were forwarded to these recipients.

```kql
let srl=pack_array("{SRL}"); //Put values from SRL here.
EmailEvents
| where RecipientEmailAddress in (srl)
| summarize Count=dcount(NetworkMessageId) by RecipientEmailAddress
```

Run this query to find out how frequently are emails forwarded to these recipients.

```kql
let srl=pack_array("{SRL}"); //Put values from SRL here.
EmailEvents
| where RecipientEmailAddress in (srl)
| summarize Count=dcount(NetworkMessageId) by RecipientEmailAddress, bin(Timestamp, 1d)
```

Run this query to find out if the email contains any URLs.

```kql
let mti='{MTI}'; //Replace {MTI} with MTI from alert
EmailUrlInfo
| where NetworkMessageId == mti
```

Run this query to find out if the email contains any attachments.

```kql
let mti='{MTI}'; //Replace {MTI} with MTI from alert
EmailAttachmentInfo
| where NetworkMessageId == mti
```

Run this query to find out if the Forwarder (sender) has created any new rules.

```kql
let sender = "{SENDER}"; //Replace {SENDER} with display name of Forwarder
let action_types = pack_array(
    "New-InboxRule",
    "UpdateInboxRules",
    "Set-InboxRule",
    "Set-Mailbox",
    "New-TransportRule",
    "Set-TransportRule");
CloudAppEvents
| where AccountDisplayName == sender
| where ActionType in (action_types)
```

Run this query to find out if there were any anomalous login events from this user. For example: unknown IPs, new applications, uncommon countries/regions, multiple LogonFailed events.

```kql
let sender = "{SENDER}"; //Replace {SENDER} with email of the Forwarder
IdentityLogonEvents
| where AccountUpn == sender
```
