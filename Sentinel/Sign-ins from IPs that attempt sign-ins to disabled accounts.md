
let Networks = _GetWatchlist('NetworkAddresses');
let lookBack = 7d;
let IncTitle = "Sign-ins from IPs that attempt sign-ins to disabled accounts";
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
| distinct AttackIPAddress


let IP_Indicators = (
(ThreatIntelligenceIndicator
| where TimeGenerated >= ago(7d) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
| where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80" and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127."));
let lookBack = 30d;
let Networks = _GetWatchlist('NetworkAddresses');
let aadFunc = (tableName:string){
table(tableName)
| where TimeGenerated > ago(lookBack)
| where ResultType == "50057"
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator."
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), disabledAccountLoginAttempts = count(),
            disabledAccountsTargeted = dcount(UserPrincipalName), applicationsTargeted = dcount(AppDisplayName), disabledAccountSet = make_set(UserPrincipalName,15),
            applicationSet = make_set(AppDisplayName,15) by IPAddress, Type
| order by disabledAccountLoginAttempts desc
| join kind= leftouter (
    // Consider these IPs suspicious - and alert any related  successful sign-ins
    table(tableName)
    | where ResultType == 0
    | summarize successfulAccountSigninCount = dcount(UserPrincipalName), successfulAccountSigninSet = make_set(UserPrincipalName,15) by IPAddress, Type
    // Assume IPs associated with sign-ins from 100+ distinct user accounts are safe
    | where successfulAccountSigninCount < 100
) on IPAddress
// IPs from which attempts to authenticate as disabled user accounts originated, and had a non-zero success rate for some other account
| where isnotempty(successfulAccountSigninCount)
| project StartTime, EndTime, IPAddress, disabledAccountLoginAttempts, disabledAccountsTargeted, disabledAccountSet, applicationSet,
successfulAccountSigninCount, successfulAccountSigninSet, Type
| order by disabledAccountLoginAttempts
| extend timestamp = StartTime
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
| extend current_geoinfo = geo_info_from_ip_address(IPAddress)
| evaluate ipv4_lookup(Networks, IPAddress, ['IP Subnet'],return_unmatched = true) 
| extend country = tostring(current_geoinfo.country)
| extend city = tostring(current_geoinfo.city)
| extend state = tostring(current_geoinfo.state)
| join kind= leftouter  IP_Indicators on $left. IPAddress == $right. NetworkSourceIP
