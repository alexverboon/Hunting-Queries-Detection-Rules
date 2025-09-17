# Microsoft Defender for Endpoint - Aggregated reporting

## Query Information

### Description

DESCRIPTION

#### References

- [Get greater visibility with aggregated reporting of endpoint telemetry signals](https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/get-greater-visibility-with-aggregated-reporting-of-endpoint-telemetry-signals/4366712)
- [Aggregated reporting in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/aggregated-reporting)

### Microsoft 365 Defender

```kql
union DeviceFileEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents
| where ActionType contains "Aggregate"
| summarize count() by ActionType


union DeviceFileEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents
| where ActionType contains "Aggregate"
| summarize count() by ActionType

DeviceFileEvents
| where ActionType == @"FileCreatedAggregatedReport"
//| distinct FolderPath
| where ActionType == @"FileRenamedAggregatedReport"
| where ActionType == @"FileModifiedAggregatedReport"

DeviceLogonEvents
| where ActionType == @"LogonSuccessAggregatedReport"


DeviceProcessEvents
| where ActionType == @"ProcessCreatedAggregatedReport"

DeviceNetworkEvents
 | where ActionType == @"ConnectionFailedAggregatedReport"
 | where ActionType == @"ConnectionSuccessAggregatedReport"
```

```kql
let aggregatedevents = union DeviceFileEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents
| where ActionType contains "Aggregate"
| where TimeGenerated > ago(90d)
| where _IsBillable == true
| summarize TotalAggregatedEventsVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d) , DeviceName
// Sum all
| summarize sum(TotalAggregatedEventsVolumeGBLog) by DeviceName;
let otherevents = union DeviceFileEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents
| where ActionType !contains "Aggregate"
| where TimeGenerated > ago(90d)
| where _IsBillable == true
| summarize TotalVolumeOtherGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d) , DeviceName
// Sum all
| summarize sum(TotalVolumeOtherGBLog) by DeviceName;
aggregatedevents
| join otherevents
on $left. DeviceName == $right. DeviceName
| project DeviceName, sum_TotalAggregatedEventsVolumeGBLog, sum_TotalVolumeOtherGBLog


union DeviceFileEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents
| where TimeGenerated > ago(90d)
| where _IsBillable == true
| summarize 
    Aggregated = sumif(_BilledSize, ActionType endswith "AggregatedReport"), 
    NAggregated = sumif(_BilledSize, ActionType !endswith "AggregatedReport"), 
    Total = sum(_BilledSize) 
    by DeviceName
| extend Percent = round((Aggregated / Total) *100,2)



