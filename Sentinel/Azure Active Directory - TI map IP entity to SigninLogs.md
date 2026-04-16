# Azure Active Directory - TI map IP entity to SigninLogs

## Query Information

### Description

The Sentinel Analytics Rule *TI map IP entity to SigninLogs* Identifies a match in SigninLogs from any IP IOC from TI

#### References


### Microsoft Sentinel

Use the below query to get a summary of Incidents

```kql
let ioc_lookBack = 90d;
let lookback = 90d;
let IncTitle = dynamic(["(Preview) TI map IP entity to SigninLogs","TI map IP entity to SigninLogs"]);
SecurityIncident
| where TimeGenerated > ago(lookback)
| where Title has_any (IncTitle)
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| join  (SecurityAlert)
on $left. AlertId == $right. SystemAlertId
| mv-expand parse_json(Entities)
| extend EType = tostring((Entities.Type))
| where EType == 'ip'
| extend IPAddress = tostring(Entities.Address)
// Count the # of alerts per IP address
| summarize Alertcount = dcount(SystemAlertId) by IPAddress
| join kind=innerunique  (ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true
    // Picking up only IOC's that contain the entities we want
    | where isnotempty(NetworkIP)
        or isnotempty(EmailSourceIpAddress)
        or isnotempty(NetworkDestinationIP)
        or isnotempty(NetworkSourceIP)
    // As there is potentially more than 1 indicator type for matching IP, taking NetworkIP first, then others if that is empty.
    // Taking the first non-empty value based on potential IOC match availability
    | extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
) on $left. IPAddress ==  $right.TI_ipEntity
| project IPAddress, Alertcount, LatestIndicatorTime, SourceSystem, ConfidenceScore, Description, ThreatType, Tags
// find the successfull sign-ins
| join SigninLogs
on $left. IPAddress == $right. IPAddress
| summarize TotalSignIns = dcount(CorrelationId), Failed = dcountif(CorrelationId, ResultType != 0), Success = dcountif(CorrelationId,ResultType == 0) , TotalUsers = dcount(UserPrincipalName)
by IPAddress, Alertcount, Description, ThreatType, Tags, AutonomousSystemNumber, Location

```

Identify the user accounts affected

```
let ioc_lookBack = 90d;
let lookback = 90d;
let IncTitle = dynamic(["TI Map IP Entity to SigninLogs - not successfull logons"]);
SecurityIncident
| where TimeGenerated > ago(lookback)
| where Title has_any (IncTitle)
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| join  (SecurityAlert)
on $left. AlertId == $right. SystemAlertId
| mv-expand parse_json(Entities)
| extend EType = tostring((Entities.Type))
| where EType == 'account'
| extend AccountName = tostring(Entities.Name)
| summarize count() by AccountName
| join kind=leftouter (IdentityInfo
| summarize arg_max(TimeGenerated,*) by AccountName)
on $left. AccountName == $right. AccountName
| project AccountName, count_, AccountUPN, AccountDisplayName
```

Check if the user has MFA enabled (requires that you have an azure ad group with these users)

```
let NoMFA = (
IdentityInfo
| where TimeGenerated > ago(30d)
| where isnotempty( GroupMembership)
| summarize arg_max(TimeGenerated,*) by AccountUPN
| project AccountUPN, GroupMembership 
| mv-expand GroupMembership
| extend GroupName = tostring(parse_json(tostring(GroupMembership)))
| where GroupName == 'AAD-SG-UserMFA-NotCapable'
//| where GroupName == 'AAD-SG-UserMFA-Capable'
| extend iAccountUPN = AccountUPN
| distinct iAccountUPN);
let ioc_lookBack = 90d;
let lookback = 90d;
let IncTitle = dynamic(["TI Map IP Entity to SigninLogs - not successfull logons"]);
SecurityIncident
| where TimeGenerated > ago(lookback)
| where Title has_any (IncTitle)
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| join  (SecurityAlert)
on $left. AlertId == $right. SystemAlertId
| mv-expand parse_json(Entities)
| extend EType = tostring((Entities.Type))
| where EType == 'account'
| extend AccountName = tostring(Entities.Name)
| summarize count() by AccountName
| join kind=leftouter (IdentityInfo
| summarize arg_max(TimeGenerated,*) by AccountName)
on $left. AccountName == $right. AccountName
| project AccountName, count_, AccountUPN, AccountDisplayName
| join kind=leftouter NoMFA
on $left. AccountUPN == $right. iAccountUPN
| extend HasMFA = iff(isempty(iAccountUPN), "Yes","No")
| project AccountUPN, AccountName, HasMFA, count_
```


Below is the original query from Sentinel, modify the lines to see successful/unsuccessful logons

            | where StatusCode == "0"
            //| where StatusCode  != "0"

```kql
let dt_lookBack = 90d;
let ioc_lookBack = 30d;
let aadFunc = (tableName: string) {
    ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true
    // Picking up only IOC's that contain the entities we want
    | where isnotempty(NetworkIP)
        or isnotempty(EmailSourceIpAddress)
        or isnotempty(NetworkDestinationIP)
        or isnotempty(NetworkSourceIP)
    // As there is potentially more than 1 indicator type for matching IP, taking NetworkIP first, then others if that is empty.
    // Taking the first non-empty value based on potential IOC match availability
    | extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
    // using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (
        table(tableName)
        | where TimeGenerated >= ago(dt_lookBack)
        | extend Status = todynamic(Status), LocationDetails = todynamic(LocationDetails)
        | extend
            StatusCode = tostring(Status.errorCode),
            StatusDetails = tostring(Status.additionalDetails),
            StatusReason = tostring(Status.failureReason)
            | where StatusCode == "0"
            //| where StatusCode  != "0"
        | extend
            State = tostring(LocationDetails.state),
            City = tostring(LocationDetails.city),
            Region = tostring(LocationDetails.countryOrRegion)
        // renaming time column so it is clear the log this came from
        | extend SigninLogs_TimeGenerated = TimeGenerated, Type = Type
        )
        on $left.TI_ipEntity == $right.IPAddress
    | where SigninLogs_TimeGenerated < ExpirationDateTime
    | summarize SigninLogs_TimeGenerated = arg_max(SigninLogs_TimeGenerated, *) by IndicatorId, IPAddress
    | project
        SigninLogs_TimeGenerated,
        Description,
        ActivityGroupNames,
        IndicatorId,
        ThreatType,
        Url,
        ExpirationDateTime,
        ConfidenceScore,
        TI_ipEntity,
        IPAddress,
        UserPrincipalName,
        AppDisplayName,
        StatusCode,
        StatusDetails,
        StatusReason,
        NetworkIP,
        NetworkDestinationIP,
        NetworkSourceIP,
        EmailSourceIpAddress,
        Type
    | extend
        timestamp = SigninLogs_TimeGenerated,
        Name = tostring(split(UserPrincipalName, '@', 0)[0]),
        UPNSuffix = tostring(split(UserPrincipalName, '@', 1)[0])
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
```
