


let MySubnets = toscalar ( _GetWatchlist('NetworkAddresses')
| summarize make_set((SearchKey)));
SigninLogs
| extend ismatch = ipv4_is_in_any_range(IPAddress,MySubnets)
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, ismatch, AppDisplayName, ClientAppUsed, city_, state_



let MySubnetsList =  _GetWatchlist('NetworkAddresses');
SigninLogs
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, city_, state_
| evaluate ipv4_lookup(MySubnetsList, IPAddress,SearchKey, return_unmatched = true)



https://www.garybushey.com/2022/05/21/azure-kql-working-with-ip-addresses/
https://ipinfo.io/products/ip-company-api
https://ipinfo.io/85.2.137.158
https://networksdb.io/ips-in-network/85.2.0.0/85.2.255.255/page/14



let MySubnets = toscalar ( _GetWatchlist('NetworkAddresses')
| summarize make_set((SearchKey)));
let IsInNetworkRnage = (SourceData:(IPAddress:string)) {
    SourceData
    | extend IsKnownNewtwork = ipv4_is_in_any_range(IPAddress, MySubnets)
};
SigninLogs
//| project TimeGenerated, UserPrincipalName, Location, IPAddress
| invoke IsInNetworkRnage()
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress,IsKnownNewtwork, Location, AppDisplayName, ClientAppUsed, city_, state_



let IP_Data =
         externaldata(network:string,geoname_id:long,continent_code:string,continent_name:string,
         country_iso_code:string,country_name:string,is_anonymous_proxy:bool,
         is_satellite_provider:bool)
         ['https://raw.githubusercontent.com/datasets/geoip2-ipv4/master/data/geoip2-ipv4.csv'];
let MySubnets = toscalar ( _GetWatchlist('NetworkAddresses')
| summarize make_set((SearchKey)));
SigninLogs
| where TimeGenerated > ago(3h)
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| evaluate ipv4_lookup(IP_Data, IPAddress,network, return_unmatched = true)
| mv-apply ip_range = MySubnets to typeof(string) on (
    extend isinrange = ipv4_is_in_range(IPAddress, ip_range)
)
| project TimeGenerated, CorrelationId, UserPrincipalName, IPAddress, Location, ip_range, isinrange, city_, state_,continent_name,country_name, country_iso_code




// network range mapping with sign-in logs
let MySubnetsList =  _GetWatchlist('NetworkAddresses');
SigninLogs
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, city_, state_
| evaluate ipv4_lookup(MySubnetsList, IPAddress,SearchKey, return_unmatched = true)
// | where isempty(["Range Name"])
| summarize count() by IPAddress, Location, Tags, ["Range Name"]


let MySubnetsList =  _GetWatchlist('NetworkAddresses');
SigninLogs
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, city_, state_
| evaluate ipv4_lookup(MySubnetsList, IPAddress,SearchKey, return_unmatched = true)
| extend IsMatch = iff(isempty(SearchKey),"No","Yes")
| project-reorder IsMatch





// shows sign in logs with information whether the ip address is in a known range
let MySubnetsList =  _GetWatchlist('NetworkAddresses');
SigninLogs
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, city_, state_
| evaluate ipv4_lookup(MySubnetsList, IPAddress,SearchKey, return_unmatched = true)
| extend IsMatch = iff(isempty(SearchKey),"No","Yes")
| project-reorder IsMatch
| where IsMatch == "Yes"
| where ["Range Name"] contains "Zscaler"
| summarize Total = count(), dcount(Location), Locations = make_set(Location), dcount(["IP Subnet"]), make_set(['IP Subnet']) by UserPrincipalName
//| summarize count() by ['Range Name'], ['IP Subnet'], Location, UserPrincipalName




// shows sign in logs with information whether the ip address is in a known range
let MySubnetsList =  _GetWatchlist('NetworkAddresses');
SigninLogs
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| project TimeGenerated,CorrelationId, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, city_, state_
| evaluate ipv4_lookup(MySubnetsList, IPAddress,SearchKey, return_unmatched = true)
| extend IsMatch = iff(isempty(SearchKey),"No","Yes")
| project-reorder IsMatch
| where IsMatch == "Yes"
| where ["Range Name"] contains "Zscaler"
//| summarize Total = count(), dcount(Location), Locations = make_set(Location), dcount(["IP Subnet"]), make_set(['IP Subnet']) by UserPrincipalName
| summarize count() by ['Range Name'], ['IP Subnet'], Location
| where ['IP Subnet'] contains '165.225.202.0/23'


externaldata (['zscalerthree.net']: string) [h'https://raw.githubusercontent.com/alexverboon/Sentinel-Content-Dev/main/ExternalData/zscalerdatacenter.json']
with(format='json')
//| mv-expand parse_json(['zscalerthree.net'])
| parse ['zscalerthree.net'] with * ': ' Continent '"' *