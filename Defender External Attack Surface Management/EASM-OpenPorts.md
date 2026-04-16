
# Defender External Attack Surface Management - Open Ports

## Query Information

### Description

Use the below queries to retrieve information about systems with Open Ports from Defender External Attack Surface Management

#### References

### Microsoft Sentinel

List all assets with Open ports

```kql
EasmIpAddressAsset_CL
| summarize arg_max(TimeGenerated,*) by IPAddress
| mv-expand parse_json(Ports_s)
| extend Components = parse_json(WebComponents_s)
| extend LastPortState = tostring(Ports_s.LastPortState)
| extend Port = tostring(Ports_s.Port)
| extend PortStateFirstSeen = todatetime(Ports_s.PortStateFirstSeen)
| extend PortStateLastSeen = todatetime(Ports_s.PortStateLastSeen)
| where LastPortState == 'OPEN' 
| mv-expand Components
| extend Category = tostring(Components.Category)
| extend Name = tostring(Components.Name)
| project TimeGenerated, IPAddress, Port, LastPortState,PortStateLastSeen,PortStateFirstSeen, Category, Name
| summarize Categories = make_set(Category), Names = make_set(Name) by IPAddress , Port//, PortStateFirstSeen, PortStateLastSeen
| sort by IPAddress, Port
```

 Telnet Service Exposure

```kql
EasmRisk_CL
| where CategoryName_s == "High Severity"
| where MetricDisplayName_s == "ASI: Telnet Service Exposure"
```

Create a watchlist with the following attributes:
IPAddress, Description, Tag, Risk

Example:
1.2.3.4,SSH Server,,"ASI: Telnet Service Exposure"

```kql
// EASM Risk Whitelist
let EASMWLTelnet = _GetWatchlist('EASMRiskWhitelist') | where ['Risk'] == 'ASI: Telnet Service Exposure'
| extend IPAddress = SearchKey
| project IPAddress;
// Servers with Telnet Service Exposure
EasmRisk_CL
| extend IPAddress = AssetName_s
| where IPAddress !in(EASMWLTelnet)
| where AssetLastSeen_t >= ago(7d)
| where CategoryName_s == "High Severity"
| where MetricDisplayName_s == "ASI: Telnet Service Exposure"
| extend Rule = tostring(parse_json(AssetDiscoveryAuditTrail_s)[0].Rule)
| project TimeGenerated, AssetType_s, AssetName_s,IPAddress, CategoryName_s, Rule, MetricDisplayName_s, AssetLastSeen_t
```

testing differences

``` kql 
// Define the time ranges
let startTime1 = now()-90d;
let endTime1 = now()-8d;
let startTime2 = now()-7d;
let endTime2 = now();
let olderdata = EasmIpAddressAsset_CL
| where TimeGenerated between (startTime1 .. endTime1)
| summarize arg_max(TimeGenerated,*) by IPAddress
| mv-expand parse_json(Ports_s)
| extend Components = parse_json(WebComponents_s)
| extend LastPortState = tostring(Ports_s.LastPortState)
| extend Port = tostring(Ports_s.Port)
| extend PortStateFirstSeen = todatetime(Ports_s.PortStateFirstSeen)
| extend PortStateLastSeen = todatetime(Ports_s.PortStateLastSeen)
| where LastPortState == 'OPEN' 
| mv-expand Components
| extend Category = tostring(Components.Category)
| extend Name = tostring(Components.Name)
| project TimeGenerated, IPAddress, Port, LastPortState,PortStateLastSeen,PortStateFirstSeen, Category, Name
| summarize Categories = make_set(Category), Names = make_set(Name) by IPAddress , Port, PortStateFirstSeen, PortStateLastSeen
//| where PortStateFirstSeen > ago(7d)
| sort by IPAddress, Port;
let newerdata = EasmIpAddressAsset_CL
| where ingestion_time() between (startTime2 .. endTime2)
| summarize arg_max(TimeGenerated,*) by IPAddress
| mv-expand parse_json(Ports_s)
| extend Components = parse_json(WebComponents_s)
| extend LastPortState = tostring(Ports_s.LastPortState)
| extend Port = tostring(Ports_s.Port)
| extend PortStateFirstSeen = todatetime(Ports_s.PortStateFirstSeen)
| extend PortStateLastSeen = todatetime(Ports_s.PortStateLastSeen)
| where LastPortState == 'OPEN' 
| mv-expand Components
| extend Category = tostring(Components.Category)
| extend Name = tostring(Components.Name)
| project TimeGenerated, IPAddress, Port, LastPortState,PortStateLastSeen,PortStateFirstSeen, Category, Name
| summarize Categories = make_set(Category), Names = make_set(Name) by IPAddress , Port, PortStateFirstSeen, PortStateLastSeen
| sort by IPAddress, Port;
olderdata
| join kind=innerunique (newerdata)
on $left. IPAddress == $right. IPAddress
```
