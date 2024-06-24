# Defender for Office 365 - QRCodes

## Query Information

### Description

Use the below queries to identify e-mails with QR Codes

### References

- [Hunting and responding to QR code-based phishing attacks with Defender for Office 365](https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/hunting-and-responding-to-qr-code-based-phishing-attacks-with/ba-p/4074730)

### Credits

All the below queries originate from the above referenced blog post from Microsoft.

### Microsoft Sentinel

```kql
EmailUrlInfo
| where UrlLocation == 'QRCode'
| project Url, UrlLocation, UrlDomain
```

```kql
// Volume of inbound emails with QR code in last 30 days:
EmailEvents
| where TimeGenerated > ago(30d)
| where EmailDirection == "Inbound"
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
| summarize dcount(NetworkMessageId) by bin(TimeGenerated, 1d)
| render timechart
```

```kql
// Emails delivered having URLs in the form of QR codes:
EmailEvents
| where TimeGenerated > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
| project TimeGenerated, NetworkMessageId, SenderFromAddress, Subject, Url, UrlDomain, UrlLocation
```

```kql
// Emails with suspicious keywords in subject:
let SubjectKeywords = ()
{
    pack_array("authorize", "authenticate", "account", "confirmation", "QR", "login", "password",  "payment", "urgent", "verify");
};
EmailEvents
| where TimeGenerated > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| where Subject has_any (SubjectKeywords)
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
```
```kql
//Sample Advanced Hunting query for emails with QR codes from non-prevalent sender:
let senderprevalence =
EmailEvents
    | where TimeGenerated  between (ago(7d)..(now()-24h))
    | where isnotempty(SenderFromAddress)
    | summarize TotalEmailCount = dcount(NetworkMessageId) by SenderFromAddress
    | where TotalEmailCount > 1;
let prevalent_Sender = senderprevalence
    | where isnotempty (SenderFromAddress)
    | distinct SenderFromAddress;
let QR_from_non_prevalent =
EmailEvents
| where EmailDirection == "Inbound"
| where TimeGenerated > ago(1d)
| where SenderFromAddress !in (prevalent_Sender)
| join EmailUrlInfo on NetworkMessageId
    | where UrlLocation == "QRCode"
    | distinct SenderFromAddress,Url,NetworkMessageId;
QR_from_non_prevalent
```

```kql
// detection rule
let QRCode_emails = EmailUrlInfo
    | where TimeGenerated > ago (2d)
    | where UrlLocation == "QRCode"
    | distinct Url,NetworkMessageId;
let nMIDs = QRCode_emails | distinct NetworkMessageId;
// Extracting sender of the email with QRCode:
let senders_NMIDs = EmailEvents
    | where TimeGenerated > ago (2d)
    | where DeliveryLocation != "Blocked" // Only delivered or Junked emails are interesting
    | where isnotempty(NetworkMessageId)
    | where NetworkMessageId in (nMIDs)
    | distinct  TimeGenerated, NetworkMessageId, RecipientEmailAddress, SenderFromAddress, InternetMessageId, RecipientObjectId, ReportId;
let senders = senders_NMIDs
    | distinct SenderFromAddress;
// Checking sender prevalence in the organization
let senderprevalence = EmailEvents
    | where TimeGenerated  between (ago(14d)..(now()-24h))
    | where isnotempty(SenderFromAddress)
    | where SenderFromAddress in (senders)
    | summarize TotalEmailCount = count()  by SenderFromAddress
    | where TotalEmailCount > 1;
let prevalent_Sender = senderprevalence
    | where isnotempty (SenderFromAddress)
    | distinct SenderFromAddress;
// Checking if in clicked emails sender was not prevalent.
let nMIDs_from_non_prevalent_Senders = senders_NMIDs
    | where SenderFromAddress !in (prevalent_Sender)
    | distinct NetworkMessageId;
let QRCode_emails_from_non_prevalent_senders = QRCode_emails
    | where NetworkMessageId in (nMIDs_from_non_prevalent_Senders)
    | join kind=inner senders_NMIDs on NetworkMessageId
    | project TimeGenerated,Url, NetworkMessageId, InternetMessageId, RecipientObjectId, ReportId;
QRCode_emails_from_non_prevalent_senders
```
