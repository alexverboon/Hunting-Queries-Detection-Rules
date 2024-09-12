# Defender for Endpoint - Exposure Level

## Query Information

### Description

Summaries of devices with Exposure Levels.

You could use this query to run in a Sentinel Summarization rule every 24 hours to keep a log of your exposure levels.

#### References

### Microsoft Sentinel

```kql
DeviceInfo
//| where TimeGenerated > ago(1d)
| where OnboardingStatus == 'Onboarded'
| summarize arg_max(TimeGenerated, *) by DeviceId
| summarize
    Low = dcountif(DeviceId, ExposureLevel == 'Low'),
    Medium = dcountif(DeviceId, ExposureLevel == 'Medium'), 
    High = dcountif(DeviceId, ExposureLevel == 'High'),
    None = dcountif(DeviceId, ExposureLevel == 'None')
| extend Time = now()    
```kql
