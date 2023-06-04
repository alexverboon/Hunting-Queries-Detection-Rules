# Azure Active Dirctory - PowerShell

## Query Information


### Description

Use the below queries to identify Azure Active Directory sign-ins with Azure Active Directory PowerShell or Microsoft Exchange Online Remote PowerShell


#### References



### Microsoft 365 Defender




```kql
let timeframe = 90d;
SigninLogs 
| where TimeGenerated >= ago(timeframe)
| where AppDisplayName has_any ("Azure Active Directory PowerShell","Microsoft Exchange Online Remote PowerShell")
| where ResultType != 0
| project TimeGenerated, Identity, Location, AlternateSignInName, AppDisplayName, AppId, DeviceDetail, IPAddress, LocationDetails, NetworkLocationDetails, AuthenticationDetails, ResultType, ResultDescription
| extend City = parse_json(LocationDetails["city"])
| extend DeviceOS = parse_json(DeviceDetail["operatingSystem"])
| extend Browser = parse_json(DeviceDetail["browser"])
| extend authenticationMethod = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod) 
| extend authenticationStepDateTime = tostring(parse_json(AuthenticationDetails)[0].authenticationStepDateTime)
| extend succeeded = tostring(parse_json(AuthenticationDetails)[0].succeeded)
| project TimeGenerated,authenticationMethod,authenticationStepDateTime,succeeded, Identity, AlternateSignInName, AppDisplayName, AppId,IPAddress, DeviceOS, Browser,Location, City, ResultType, ResultDescription
```



