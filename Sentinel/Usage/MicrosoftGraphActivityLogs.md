

// Total ingestion in GB
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(90d)
| where _IsBillable == true
| summarize TotalVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d)
// Sum all
| summarize sum(TotalVolumeGBLog)



// Combine Usage and Log Data
let ingestionprice = 5.59;
let logsource = "MicrosoftGraphActivityLogs";
let xusage = Usage
| where TimeGenerated > ago (30d)
| where IsBillable == true
| summarize TotalVolumeGBUsage = round(sum(Quantity/1024),2) by bin(TimeGenerated, 1d), DataType
| where DataType == (logsource);
MicrosoftGraphActivityLogs
| where TimeGenerated > ago  (30d)
| where _IsBillable == true
| summarize TotalVolumeGBLog = round(sum(_BilledSize/1024/1024/1024),2)  by bin(TimeGenerated, 1d)
| join xusage
on $left.TimeGenerated ==  $right.TimeGenerated
| extend ['Estimated cost'] = TotalVolumeGBLog * ingestionprice
//| summarize sum(TotalVolumeGBUsage), sum(TotalVolumeGBLog)


https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/microsoft-graph-activity-log-is-now-available-in-public-preview/ba-p/3848269

Summarize applications and principals that have made requests to change or delete groups in the past day:
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestUri contains '/group'
| where RequestMethod != "GET"
| summarize UriCount=dcount(RequestUri) by AppId, UserId, ServicePrincipalId, ResponseStatusCode

To see recent requests that failed due to authorization:
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1h)
| where ResponseStatusCode == 401 or ResponseStatusCode == 403
| project AppId, UserId, ServicePrincipalId, ResponseStatusCode, RequestUri, RequestMethod
| limit 1000


Get top 20 app instances by request count:


MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| summarize RequestCount=count() by AppId, IpAddress, UserAgent
| sort by RequestCount
| limit 20

