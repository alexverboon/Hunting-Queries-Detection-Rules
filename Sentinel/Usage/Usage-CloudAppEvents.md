# Usage - CloudAppEvents

## Query Information

### Description

The CloudAppEvents table in the advanced hunting schema contains information about events involving accounts and objects in Office 365 and other cloud apps and services.

Use the below queries to review the data usage within the CloudAppEvents table in Microsoft Sentinel. 

#### References

- [CloudAppEvents](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-cloudappevents-table?view=o365-worldwide)


### Microsoft Sentinel

// Total ingestion in GB into the CloudAppEvents table

```kql
CloudAppEvents
| where TimeGenerated > ago(90d)
| where _IsBillable == true
| summarize TotalVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d) 
// Sum all
| summarize sum(TotalVolumeGBLog) 
```kql

Total ingestion in GB into the CloudAppEvents table, broken down by application that is connected via
the App Connector in Defender for Cloud Apps

```kql
CloudAppEvents
| where TimeGenerated > ago(90d)
| where _IsBillable == true
| summarize TotalVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d), Application
// Sum all
| summarize round(sum(TotalVolumeGBLog),2) by Application
| render columnchart  
```kql

// here we're comparing the Ingested GB between the CloudAppEvents and the Usage table. 
// You might have to adjust the ingestionprice for Sentinel/LogAnalytics.

```kql
let ingestionprice = 5.59;
let logsource = "CloudAppEvents";
let xusage = Usage
| where TimeGenerated > ago (30d)
| where IsBillable == true
| summarize TotalVolumeGBUsage = round(sum(Quantity/1024),2) by bin(TimeGenerated, 1d), DataType
| where DataType == (logsource);
CloudAppEvents
| where TimeGenerated > ago  (30d)
| where _IsBillable == true
| summarize TotalVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d)
| join xusage
on $left.TimeGenerated ==  $right.TimeGenerated
| extend ['Estimated cost'] = TotalVolumeGBLog * ingestionprice
| summarize  round(sum(TotalVolumeGBUsage),2), round(sum(TotalVolumeGBLog),2) , round(sum(['Estimated cost']),2)
```

// show how much the CloudAppEvents data usage compares to the rest of the logs. 
```kql
Usage
| where TimeGenerated > ago (30d)
| where IsBillable == true
| summarize TotalVolumeGBUsage = round(sum(Quantity/1024),2) by DataType
| summarize CloudAppEvents = sumif(TotalVolumeGBUsage, DataType == 'CloudAppEvents'), OtherLogs = round(sumif(TotalVolumeGBUsage,DataType != 'CloudAppEvents'),2)
| extend Pct = round(CloudAppEvents*100/OtherLogs,2)
```
