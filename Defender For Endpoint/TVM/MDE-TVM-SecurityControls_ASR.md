# MDE - TVM - Security Configuration - Attack Surface Reduction Rules

## Query Information

Use the below query to retrieve Attack Surface Reduction Rules configuration compliance

#### References

### Microsoft 365 Defender


```kql
//  Security Controls - Attack Surface Reduction - Compliance Summary 
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-2514","scid-2513","scid-2512","scid-2511","scid-2510","scid-2509","scid-2508","scid-2507","scid-2506","scid-2505","scid-2504","scid-2503","scid-2502","scid-2501","scid-2500")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-2541", "BlockPersWMIEventSubscr",
    ConfigurationId == "scid-2513", "BlockAdobeChildProcess",
    ConfigurationId == "scid-2512", "BlockAsrOfficeCommAppChildProcess",
    ConfigurationId == "scid-2511", "BlockAsrUntrustedUsbProcess",
    ConfigurationId == "scid-2510", "BlockAsrPsexecWmiChildProcess",
    ConfigurationId == "scid-2509", "BlocAsrLsassCredentialTheft",
    ConfigurationId == "scid-2508", "AdvProtRansomware",
    ConfigurationId == "scid-2507", "BlockAsrUntrustedExecutable",
    ConfigurationId == "scid-2506", "BlockAsrOfficeMacroWin32ApiCalls",
    ConfigurationId == "scid-2505", "BlockObfuscatedScripts",
    ConfigurationId == "scid-2504", "BlockJavaVBExecContent",
    ConfigurationId == "scid-2503", "BlockAsrOfficeProcessInjection",
    ConfigurationId == "scid-2502", "BlockAsrExecutableOfficeContent",
    ConfigurationId == "scid-2501", "BlockAsrOfficeChildProcess",
    ConfigurationId == "scid-2500", "BlockAsrExecutableEmailContent",
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
// Security Controls - Attack Surface Reduction - Non-Compliance Details
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-2514","scid-2513","scid-2512","scid-2511","scid-2510","scid-2509","scid-2508","scid-2507","scid-2506","scid-2505","scid-2504","scid-2503","scid-2502","scid-2501","scid-2500")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-2541", "BlockPersWMIEventSubscr",
    ConfigurationId == "scid-2513", "BlockAdobeChildProcess",
    ConfigurationId == "scid-2512", "BlockAsrOfficeCommAppChildProcess",
    ConfigurationId == "scid-2511", "BlockAsrUntrustedUsbProcess",
    ConfigurationId == "scid-2510", "BlockAsrPsexecWmiChildProcess",
    ConfigurationId == "scid-2509", "BlocAsrLsassCredentialTheft",
    ConfigurationId == "scid-2508", "AdvProtRansomware",
    ConfigurationId == "scid-2507", "BlockAsrUntrustedExecutable",
    ConfigurationId == "scid-2506", "BlockAsrOfficeMacroWin32ApiCalls",
    ConfigurationId == "scid-2505", "BlockObfuscatedScripts",
    ConfigurationId == "scid-2504", "BlockJavaVBExecContent",
    ConfigurationId == "scid-2503", "BlockAsrOfficeProcessInjection",
    ConfigurationId == "scid-2502", "BlockAsrExecutableOfficeContent",
    ConfigurationId == "scid-2501", "BlockAsrOfficeChildProcess",
    ConfigurationId == "scid-2500", "BlockAsrExecutableEmailContent",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| where IsCompliant == 0    
| join kind=leftouter  DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| project DeviceName, ConfigurationName, ConfigurationSubcategory, ConfigurationCategory
| sort by DeviceName, ConfigurationSubcategory
```
