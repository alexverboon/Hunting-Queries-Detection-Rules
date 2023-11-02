# Defender for Office 365 - Authentication Details

## Query Information

### Description

Use the below queries to get Authentication details from e-mail send thorugh Microsoft Defender for Office 365

#### References

- [Advanced Hunting: Surfacing more email data from Microsoft Defender for Office 365](https://techcommunity.microsoft.com/t5/microsoft-365-defender-blog/advanced-hunting-surfacing-more-email-data-from-microsoft/ba-p/2678118)

### Microsoft 365 Defender

Check for spoofing attempts on the domain with SPF fails

```kql
EmailEvents |where Timestamp > ago (1d) and DetectionMethods contains "spoof" and SenderFromDomain has "contoso.com" 
| project Timestamp, AR=parse_json(AuthenticationDetails) , NetworkMessageId, EmailDirection, Subject, SenderFromAddress, SenderIPv4,ThreatTypes, DetectionMethods, ThreatNames 
| evaluate bag_unpack(AR) 
| where SPF == "fail" 
```
