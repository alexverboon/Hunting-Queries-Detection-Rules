
let Network_scalar = toscalar ( _GetWatchlist('NetworkAddresses')
| summarize make_set((SearchKey)));
let Networks = _GetWatchlist('NetworkAddresses');
// We can use this configuration TimeDeltaInMinutes if you want to chnage the time window that we try to match the alerts
let lookback = 90d;
let TimeDeltaInMinutes = 10;
let Alert_UnfamiliarSignInProps = 
SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProductName =~ "Azure Active Directory Identity Protection"
| where AlertName =~ "Unfamiliar sign-in properties"
| mv-expand Entity = todynamic(Entities)
| where Entity.Type =~ "account"
| extend AadTenantId = tostring(Entity.AadTenantId)
| extend AadUserId = tostring(Entity.AadUserId)
| join kind=inner (
IdentityInfo
| distinct AccountTenantId, AccountObjectId, AccountUPN, AccountDisplayName
| extend UserName = AccountDisplayName
| extend UserAccount = AccountUPN
| where isnotempty(AccountDisplayName) and isnotempty(UserAccount)
| project AccountTenantId, AccountObjectId, UserAccount, UserName
)
on
$left.AadTenantId == $right.AccountTenantId,
$left.AadUserId == $right.AccountObjectId
| extend CompromisedEntity = iff(CompromisedEntity == "N/A" or isempty(CompromisedEntity), UserAccount, CompromisedEntity)
| extend Alert_UnfamiliarSignInProps_Time = TimeGenerated
| extend Alert_UnfamiliarSignInProps_Name = AlertName
| extend Alert_UnfamiliarSignInProps_Severity = AlertSeverity
| project AadTenantId, AadUserId, AccountTenantId, AccountObjectId, Alert_UnfamiliarSignInProps_Name, Alert_UnfamiliarSignInProps_Severity, Alert_UnfamiliarSignInProps_Time, UserAccount, UserName
;
let Alert_AtypicalTravels = 
SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProductName =~ "Azure Active Directory Identity Protection"
| where AlertName =~ "Atypical travel"
| mv-expand Entity = todynamic(Entities)
| where Entity.Type =~ "account"
| extend AadTenantId = tostring(Entity.AadTenantId)
| extend AadUserId = tostring(Entity.AadUserId)
| join kind=inner (
IdentityInfo
| distinct AccountTenantId, AccountObjectId, AccountUPN, AccountDisplayName
| extend UserName = AccountDisplayName
| extend UserAccount = AccountUPN
| where isnotempty(AccountDisplayName) and isnotempty(UserAccount)
| project AccountTenantId, AccountObjectId, UserAccount, UserName
)
on
$left.AadTenantId == $right.AccountTenantId,
$left.AadUserId == $right.AccountObjectId
| extend CompromisedEntity = iff(CompromisedEntity == "N/A" or isempty(CompromisedEntity), UserAccount, CompromisedEntity)
| extend Alert_AtypicalTravels_Time = TimeGenerated
| extend Alert_AtypicalTravels_Name = AlertName
| extend Alert_AtypicalTravels_Severity = AlertSeverity
| extend ExtendedProperties_json= parse_json(ExtendedProperties)
| extend CurrentLocation = tostring(ExtendedProperties_json.["Current Location"])
| extend PreviousLocation = tostring(ExtendedProperties_json.["Previous Location"])
| extend CurrentIPAddress = tostring(ExtendedProperties_json.["Current IP Address"])
| extend PreviousIPAddress = tostring(ExtendedProperties_json.["Previous IP Address"])
| project AadTenantId, AadUserId, AccountTenantId, AccountObjectId, Alert_AtypicalTravels_Name, Alert_AtypicalTravels_Severity, Alert_AtypicalTravels_Time, CurrentIPAddress, PreviousIPAddress, CurrentLocation, PreviousLocation, UserAccount, UserName, CompromisedEntity
;
Alert_UnfamiliarSignInProps
| join kind=inner Alert_AtypicalTravels on UserAccount
| where abs(datetime_diff('minute', Alert_UnfamiliarSignInProps_Time, Alert_AtypicalTravels_Time)) <= TimeDeltaInMinutes
| extend TimeDelta = Alert_UnfamiliarSignInProps_Time - Alert_AtypicalTravels_Time
| project UserAccount, Alert_UnfamiliarSignInProps_Name, Alert_UnfamiliarSignInProps_Severity, Alert_UnfamiliarSignInProps_Time, Alert_AtypicalTravels_Name, Alert_AtypicalTravels_Severity, Alert_AtypicalTravels_Time, TimeDelta, CurrentLocation, PreviousLocation, CurrentIPAddress, PreviousIPAddress, UserName
| extend UserEmailName = split(UserAccount,'@')[0], UPNSuffix = split(UserAccount,'@')[1]
| extend current_geoinfo = geo_info_from_ip_address(CurrentIPAddress)
| extend current_country = tostring(current_geoinfo.country)
| extend current_city = tostring(current_geoinfo.city)
| extend current_state = tostring(current_geoinfo.state)
| extend current_longitude = toint(current_geoinfo.longitude)
| extend current_latitude = toint(current_geoinfo.latitude)
| extend previous_geoinfo = geo_info_from_ip_address(PreviousIPAddress)
| extend previous_country = tostring(previous_geoinfo.country)
| extend previous_city = tostring(previous_geoinfo.city)
| extend previous_state = tostring(previous_geoinfo.state)
| extend previous_longitude = toint(previous_geoinfo.longitude)
| extend previous_latitude = toint(previous_geoinfo.latitude)
| project-away current_geoinfo,previous_geoinfo, CurrentLocation, PreviousLocation, UserEmailName, UPNSuffix //current_longitude, current_latitude, 
| extend distance_km = round(geo_distance_2points(current_longitude, current_latitude, previous_longitude, previous_latitude) / 1000)
//| evaluate ipv4_lookup(Networks, CurrentIPAddress, ['IP Subnet'],return_unmatched = true) 
//| evaluate ipv4_lookup(Network, PreviousIPAddress, ['IP Subnet'],return_unmatched = true)
| extend CurrentIPMatch = ipv4_is_in_any_range(CurrentIPAddress,Network_scalar)
| extend PreviousIPMatch = ipv4_is_in_any_range(PreviousIPAddress,Network_scalar)
| where CurrentIPMatch == true
| where PreviousIPMatch == true
//| summarize count() by UserAccount
//| summarize count() by previous_country, current_country


