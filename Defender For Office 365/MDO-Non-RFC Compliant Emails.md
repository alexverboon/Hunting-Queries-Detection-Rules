# Defender for Office 365 - Identify Non-RFC Compliant Emails

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                                               | Link                                                         |
|--------------|-----------------------------------------------------|--------------------------------------------------------------|
| T1566        | Phishing                                            | https://attack.mitre.org/techniques/T1566                    |
| T1036        | Masquerading                                        | https://attack.mitre.org/techniques/T1036                    |
| T1589.002    | Gather Victim Identity Information: Email Addresses | https://attack.mitre.org/techniques/T1589/002                |
| T1557        | Adversary-in-the-Middle                             | https://attack.mitre.org/techniques/T1557                    |
| T1586.002    | Compromise Accounts: Email Accounts                 | https://attack.mitre.org/techniques/T1586/002                |

### Description

Use the below query to find Non-RFC Compliant Emails in Microsoft Defender for Office 365.

#### References

- [Strengthening Email Security: Our New Approach to Non-RFC Compliant Emails](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-security-our-new-approach-to-non-rfc-compliant-emails/4338306)
- [Email Events Table in advanced hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)
- [RFC 5322  Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322)

### Microsoft Defender XDR

Look for P2Sender addresses that do NOT match a simple RFC-like pattern:
P2 sender (or “header sender”) is the address that appears in the actual From: header of the message as seen by recipients (the RFC 5322 “From:” field).

```kql
EmailEvents
| where Timestamp >= ago(90d)
| where not(SenderFromAddress matches regex @"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$")
| project Timestamp,
          SenderMailFromAddress,
          SenderFromAddress,
          Subject,
          RecipientEmailAddress,
          DeliveryAction,
          NetworkMessageId
| order by Timestamp desc
| summarize count() by SenderFromAddress
```
