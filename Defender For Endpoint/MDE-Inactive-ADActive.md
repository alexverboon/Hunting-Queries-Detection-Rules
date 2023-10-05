# MDE - Defender for Endpoint Inactive devices with Active Directory logon activity

## Query Information

### Description

Use the below queries to identify devices that are onboarded or not onboarded in Microsoft Defender for Endpoint, but have Actiive Directory activity, meaning that an account logon event was detected on the device

#### References

### Microsoft 365 Defender

```kql
DeviceInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp,*) by DeviceName
| where OnboardingStatus == 'Onboarded' or OnboardingStatus == 'Can be onboarded'
| extend LastActiveDate = Timestamp
| where LastActiveDate < ago(7d)
| project Timestamp, LastActiveDate, DeviceName, OSPlatform, IsAzureADJoined
| join kind=leftouter  (IdentityLogonEvents
| where Timestamp > ago(7d)
| where isnotempty( AccountName)
| summarize arg_max(Timestamp,*) by DeviceName
| extend LastLogonDate = Timestamp)
on $left. DeviceName == $right. DeviceName
| where isnotempty( DeviceName1)
```

### Microsoft Sentinel

```kql
DeviceInfo
| where TimeGenerated > ago(90d)
| summarize arg_max(TimeGenerated,*) by DeviceName
| where OnboardingStatus == 'Onboarded' or OnboardingStatus == 'Can be onboarded'
| extend LastActiveDate = Timestamp
| where LastActiveDate < ago(30d)
| project TimeGenerated, LastActiveDate, DeviceName, OSPlatform, IsAzureADJoined
| join kind=leftouter  (IdentityLogonEvents
| where TimeGenerated > ago(30d)
| where isnotempty( AccountName)
| summarize arg_max(TimeGenerated,*) by DeviceName
| extend LastLogonDate = TimeGenerated)
on $left. DeviceName == $right. DeviceName
| where isnotempty( DeviceName1)

```
