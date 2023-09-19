# MDE - TVM - Security Configuration - Laps (legacy)

## Query Information

Use the below query to retrieve LAPS configuration compliance

#### References

### Microsoft 365 Defender


```kql
// Accounts - Enable Local Administrator Password Solution Compliance Overview
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-84")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-84", "Enable LAPS",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| summarize toint(Compliant = dcountif(DeviceId ,Result=="GOOD")) ,toint(NonCompliant = dcountif(DeviceId,Result=="BAD")), toint(NotApplicable = dcountif(DeviceId, Result =="N/A")) by Configuration, ConfigurationId
| join DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| extend TotalDevices = toint((Compliant + NonCompliant + NotApplicable))
| extend PctCompliant = toint((Compliant*100) / TotalDevices)
| project ConfigurationName, Compliant,NonCompliant, NotApplicable,TotalDevices, PctCompliant, ConfigurationDescription, ConfigurationCategory, RiskDescription 
```

```kql
// Local Administrator Password Solution - Non-Compliance Details
let DeviceOSInfo = DeviceInfo | where isnotempty(OSVersionInfo)
| summarize arg_max(Timestamp,*)by DeviceId;
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-84")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-84", "Enable LAPS",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| where IsCompliant == 0    
| join kind=leftouter  DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| project DeviceName, ConfigurationName, ConfigurationCategory, DeviceId
| join kind= leftouter  (DeviceOSInfo)
on $left. DeviceId ==  $right.DeviceId
```

