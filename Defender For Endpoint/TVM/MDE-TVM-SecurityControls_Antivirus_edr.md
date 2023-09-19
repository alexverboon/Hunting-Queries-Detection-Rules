# MDE - TVM - Security Configuration - Microsoft Defender - EDR

## Query Information

Use the below query to retrieve Microsoft Defender - EDR configuration compliance

#### References

### Microsoft 365 Defender


```kql
//  Security Controls - Antivirus-EDR - Compliance Summary 
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-91", "scid-2000", "scid-2001", "scid-2002", "scid-2003", "scid-2010", "scid-2011", "scid-2012", "scid-2013", "scid-2014", "scid-2016")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-2000", "SensorEnabled",
    ConfigurationId == "scid-2001", "SensorDataCollection",
    ConfigurationId == "scid-2002", "ImpairedCommunications",
    ConfigurationId == "scid-2003", "TamperProtection",
    ConfigurationId == "scid-2010", "AntivirusEnabled",
    ConfigurationId == "scid-2011", "AntivirusSignatureVersion",
    ConfigurationId == "scid-2012", "RealtimeProtection",
    ConfigurationId == "scid-91", "BehaviorMonitoring",
    ConfigurationId == "scid-2013", "PUAProtection",
    ConfigurationId == "scid-2014", "AntivirusReporting",
    ConfigurationId == "scid-2016", "CloudProtection",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| summarize toint(Compliant = dcountif(DeviceId ,Result=="GOOD")) ,toint(NonCompliant = dcountif(DeviceId,Result=="BAD")), toint(NotApplicable = dcountif(DeviceId, Result =="N/A")) by Configuration, ConfigurationId
| join DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| extend TotalDevices = toint((Compliant + NonCompliant + NotApplicable))
| extend PctCompliant = toint((Compliant*100) / TotalDevices)
| project ConfigurationName, ConfigurationSubcategory, Compliant,NonCompliant, NotApplicable,TotalDevices, PctCompliant, ConfigurationDescription, ConfigurationCategory, RiskDescription 
| sort by ConfigurationSubcategory
// | summarize by ConfigurationName, Compliant,NonCompliant, NotApplicable
// | render barchart with(kind=stacked) 
```kql

```kql
// SecurityControls - Antivirus-EDR - Non-Compliance Details
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-91", "scid-2000", "scid-2001", "scid-2002", "scid-2003", "scid-2010", "scid-2011", "scid-2012", "scid-2013", "scid-2014", "scid-2016")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-2000", "SensorEnabled",
    ConfigurationId == "scid-2001", "SensorDataCollection",
    ConfigurationId == "scid-2002", "ImpairedCommunications",
    ConfigurationId == "scid-2003", "TamperProtection",
    ConfigurationId == "scid-2010", "AntivirusEnabled",
    ConfigurationId == "scid-2011", "AntivirusSignatureVersion",
    ConfigurationId == "scid-2012", "RealtimeProtection",
    ConfigurationId == "scid-91", "BehaviorMonitoring",
    ConfigurationId == "scid-2013", "PUAProtection",
    ConfigurationId == "scid-2014", "AntivirusReporting",
    ConfigurationId == "scid-2016", "CloudProtection",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| where IsCompliant == 0    
| join kind=leftouter  DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| project DeviceName, ConfigurationName, ConfigurationSubcategory, ConfigurationCategory
| sort by DeviceName, ConfigurationSubcategory
```

```kql
// Devices with MAPS issues including network and device OS details
let configurationid = 'scid-2014';
let securityconfigurationState = 
// SecurityControls - Antivirus-EDR - Non-Compliance Details
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-91", "scid-2000", "scid-2001", "scid-2002", "scid-2003", "scid-2010", "scid-2011", "scid-2012", "scid-2013", "scid-2014", "scid-2016")
| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId, DeviceName
| extend Configuration = case(
    ConfigurationId == "scid-2000", "SensorEnabled",
    ConfigurationId == "scid-2001", "SensorDataCollection",
    ConfigurationId == "scid-2002", "ImpairedCommunications",
    ConfigurationId == "scid-2003", "TamperProtection",
    ConfigurationId == "scid-2010", "AntivirusEnabled",
    ConfigurationId == "scid-2011", "AntivirusSignatureVersion",
    ConfigurationId == "scid-2012", "RealtimeProtection",
    ConfigurationId == "scid-91", "BehaviorMonitoring",
    ConfigurationId == "scid-2013", "PUAProtection",
    ConfigurationId == "scid-2014", "AntivirusReporting",
    ConfigurationId == "scid-2016", "CloudProtection",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| where IsCompliant == 0    
| join kind=leftouter  DeviceTvmSecureConfigurationAssessmentKB 
on $left.ConfigurationId == $right.ConfigurationId
| project DeviceName,DeviceId,ConfigurationName, ConfigurationSubcategory, ConfigurationCategory, ConfigurationId
| sort by DeviceName, ConfigurationSubcategory, ConfigurationName
| where ConfigurationId == configurationid;
let DeviceInformation =
DeviceInfo
| where isnotempty( OSPlatform) 
| summarize arg_max(Timestamp,*) by DeviceId
| where OnboardingStatus == 'Onboarded'
| project DeviceId, DeviceName, MachineGroup, OSPlatform, DeviceType, OSVersionInfo
| join kind= leftouter  (DeviceNetworkInfo
| where NetworkAdapterStatus != "Down"
| where NetworkAdapterStatus != 'Dormant'
| mv-expand parse_json(IPAddresses)
| extend IPAddress = tostring(parse_json(IPAddresses).IPAddress)
| extend SubnetPrefix = tostring(parse_json(IPAddresses).SubnetPrefix)
| extend AddressType = tostring(parse_json(IPAddresses).AddressType)
| extend DefaultGateway = tostring(parse_json(DefaultGateways)[0])
| extend NetworkName = tostring(parse_json(ConnectedNetworks)[0].Name)
| where IPAddress  !startswith "fe:"
| where AddressType != "LinkLocal"
| where ConnectedNetworks != ''
| summarize arg_max(Timestamp,*) by DeviceId)
on $left.DeviceId == $right.DeviceId;
securityconfigurationState
| join kind=leftouter (DeviceInformation) 
on $left.DeviceId == $right.DeviceId
| project ConfigurationName, DeviceId, DeviceName, DeviceType, OSPlatform,OSVersionInfo, MachineGroup, MacAddress, NetworkAdapterType, IPAddress, DefaultGateway, NetworkName, IPv4Dhcp
```



