# Defender for Endpoint- Onboarding Status Information

## Query Information

### Description

Use the below query to see onboarding status changes

#### References

### Microsoft 365 Defender

Show visual timeline of Onboarding Status Changes

```kql
DeviceInfo
| where Timestamp > ago(30d)
| where DeviceName contains "<DEVICE NAME>"
| summarize FirstRecord = arg_min(Timestamp, *) by bin(Timestamp, 1d) 
| distinct Timestamp, OnboardingStatus, count=1
| render timechart

```

```kql
let osPlatforms = dynamic([
    "Windows10",
    "Windows11",
    "WindowsServer2022",
    "Linux",
    "WindowsServer2019",
    "Windows",
    "WindowsServer2016",
    "WindowsServer2012R2",
    //"Android",
    //"iOS",
    "macOS"
]);
DeviceInfo
| where OSPlatform has_any (osPlatforms)
| where isnotempty( OnboardingStatus)
| summarize
    Onboarded = dcountif(DeviceName, OnboardingStatus == "Onboarded",4),
    OnboardedDevices = make_set_if(DeviceName, OnboardingStatus == "Onboarded"),
    CanbeOnboarded = dcountif(DeviceName, OnboardingStatus == "Can be onboarded",4),
    CanbeOnboardedDevices = make_set_if(DeviceName, OnboardingStatus == "Can be onboarded"),
    InsufficientInfo = dcountif(DeviceName, OnboardingStatus == "Insufficient info",4),
    Unsupported = dcountif(DeviceName,OnboardingStatus == "Unsupported",4)
    by bin(TimeGenerated, 1d)
| extend TotalDevices = Onboarded + CanbeOnboarded + InsufficientInfo + Unsupported
//| extend TotalOnboarded = array_length(OnboardedDevices)
| serialize 
| sort by TimeGenerated desc 
| extend PreviousOnboardedDevices = next(OnboardedDevices)
| extend TotalPreviousOnboardedDevices = array_length(PreviousOnboardedDevices)
| extend OnboardedDelta = Onboarded - TotalPreviousOnboardedDevices
| sort by TimeGenerated desc
| project TimeGenerated, TotalDevices, Onboarded, TotalPreviousOnboardedDevices,OnboardedDelta, CanbeOnboarded, CanbeOnboardedDevices,Unsupported, InsufficientInfo
```
