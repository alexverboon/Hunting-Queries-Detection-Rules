# Password spray attack against Azure AD application

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.003 | Credential Access: Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

### Description

The below query looks at all past Sentinel Incidents for "Password spray attack against Azure AD application" and retrieves the Attackers IP Address, location and other properties. 


#### References


### Microsoft Sentinel


```kql
let lookBack = 7d;
let IncTitle = "Password spray attack against Azure AD application";
let AttackerIpAddresses = (
SecurityIncident
| where TimeGenerated > ago(lookBack)
| where Title == IncTitle
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| join  (SecurityAlert)
on $left. AlertId == $right. SystemAlertId
| mv-expand parse_json(Entities)
| extend EType = tostring((Entities.Type))
| extend AttackIPAddress = tostring(Entities.Address)
| project AttackIPAddress);
AttackerIpAddresses
| join (SigninLogs
| extend city = tostring(LocationDetails.city)
| extend latitude = tostring(parse_json(tostring(LocationDetails.geoCoordinates)).latitude)
| extend longitude = tostring(parse_json(tostring(LocationDetails.geoCoordinates)).longitude)
| project IPAddress, Location, city, UserAgent, ClientAppUsed, AppDisplayName, UserPrincipalName,ResultType, latitude, longitude
)
on $left. AttackIPAddress == $right. IPAddress 
| distinct AttackIPAddress, Location,city

```

