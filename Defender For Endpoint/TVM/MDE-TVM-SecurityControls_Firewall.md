# MDE - TVM - Security Configuration - Windows Firewall

## Query Information

Use the below query to retrieve Windows Firewall configuration compliance

#### References

### Microsoft 365 Defender


```kql
//  Security Controls - Firewall - Compliance Summary 
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-51","scid-50","scid-49","scid-46","scid-43","scid-2073","scid-2072","scid-2071","scid-2070")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-51", "DisableMergeFWConnectionRules",
    ConfigurationId == "scid-50", "DisableMergeFWRules",
    ConfigurationId == "scid-49", "DisableFWNotProgPublic",
    ConfigurationId == "scid-46", "DisableFWNotProgPrivate",
    ConfigurationId == "scid-43", "DisableFWNotProgDomain",
    ConfigurationId == "scid-2073", "SecFwPublic",
    ConfigurationId == "scid-2072", "SecFwPrivate",
    ConfigurationId == "scid-2071", "SecFwDomain",
    ConfigurationId == "scid-2070", "TurnOnFw",
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
// Security Controls - Firewall - Non-Compliance Details
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-51","scid-50","scid-49","scid-46","scid-43","scid-2073","scid-2072","scid-2071","scid-2070")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-51", "DisableMergeFWConnectionRules",
    ConfigurationId == "scid-50", "DisableMergeFWRules",
    ConfigurationId == "scid-49", "DisableFWNotProgPublic",
    ConfigurationId == "scid-46", "DisableFWNotProgPrivate",
    ConfigurationId == "scid-43", "DisableFWNotProgDomain",
    ConfigurationId == "scid-2073", "SecFwPublic",
    ConfigurationId == "scid-2072", "SecFwPrivate",
    ConfigurationId == "scid-2071", "SecFwDomain",
    ConfigurationId == "scid-2070", "TurnOnFw",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| where IsCompliant == 0    
| join kind=leftouter  DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| project DeviceName, ConfigurationName, ConfigurationSubcategory, ConfigurationCategory
| sort by DeviceName, ConfigurationSubcategory

```
