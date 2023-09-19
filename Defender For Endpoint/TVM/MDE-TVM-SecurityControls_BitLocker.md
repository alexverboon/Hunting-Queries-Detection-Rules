# MDE - TVM - Security Configuration - Windows Bitlocker

## Query Information

Use the below query to retrieve Windows Bitlocker configuration compliance

#### References

### Microsoft 365 Defender


```kql
//  Security Controls - BitLocker - Compliance Summary 
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-2093","scid-2091","scid-2090")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-2093", "BitLockerDriveCompat",
    ConfigurationId == "scid-2091", "ResumeBitLockerAllDrives",
    ConfigurationId == "scid-2090", "EncryptAllSupportedDrives",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| summarize toint(Compliant = dcountif(DeviceId ,Result=="GOOD")) ,toint(NonCompliant = dcountif(DeviceId,Result=="BAD")), toint(NotApplicable = dcountif(DeviceId, Result =="N/A")) by Configuration, ConfigurationId
| join DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| extend TotalDevices = toint((Compliant + NonCompliant + NotApplicable))
| extend PctCompliant = toint((Compliant*100) / TotalDevices)
| project ConfigurationName, ConfigurationSubcategory, Compliant,NonCompliant, NotApplicable,TotalDevices, PctCompliant, ConfigurationDescription, ConfigurationCategory, RiskDescription 
| sort by ConfigurationSubcategory
// | summarize by ConfigurationName, TotalDevices,Compliant,NonCompliant
// | render columnchart with(kind=stacked100) 
```

```kql
// Security Controls - BitLocker - Non-Compliance Details
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-2093","scid-2091","scid-2090")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-2093", "BitLockerDriveCompat",
    ConfigurationId == "scid-2091", "ResumeBitLockerAllDrives",
    ConfigurationId == "scid-2090", "EncryptAllSupportedDrives",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| where IsCompliant == 0    
| join kind=leftouter  DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| project DeviceName, ConfigurationName, ConfigurationSubcategory, ConfigurationCategory
| sort by DeviceName, ConfigurationSubcategory, ConfigurationName
```
