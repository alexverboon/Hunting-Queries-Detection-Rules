
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
| extend Port_ = tostring(Ports_s.Port)
| extend PortStateFirstSeen = tostring(Ports_s.PortStateFirstSeen)
| extend PortStateLastSeen = tostring(Ports_s.PortStateLastSeen)
| project TimeGenerated, IPAddress, Port_, LastPortState,PortStateLastSeen , PortStateFirstSeen, Components 
| where LastPortState == 'OPEN'
```

 Telnet Service Exposure

```kql
EasmRisk_CL
| where CategoryName_s == "High Severity"
| where MetricDisplayName_s == "ASI: Telnet Service Exposure"
```