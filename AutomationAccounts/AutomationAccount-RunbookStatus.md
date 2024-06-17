# Azure Automation Account - Runbook Job Status

## Query Information

### Description

Use the following query to get the status of your Automation Account Runbook jobs

#### References

- [Forward Azure Automation diagnostic logs to Azure Monitor](https://learn.microsoft.com/en-us/azure/automation/automation-manage-send-joblogs-log-analytics)
- [How to send custom Azure Automation Runbook logs to Log Analytics](https://andrewmatveychuk.com/how-to-send-custom-azure-automation-runbook-logs-to-log-analytics/)

### Microsoft Sentinel

```kql
AzureDiagnostics
| where Category == 'JobLogs'
| extend RunbookName = RunbookName_s
| project TimeGenerated,RunbookName,ResultType,CorrelationId,JobId_g
| summarize StartTime = minif(TimeGenerated,ResultType == 'Started'),EndTime = minif(TimeGenerated,ResultType in ('Completed','Failed','Failed')),
Status = tostring(parse_json(make_list_if(ResultType,ResultType in ('Completed','Failed','Stopped')))[0]) by JobId_g,RunbookName
| extend DurationSec = datetime_diff('second', EndTime,StartTime)
| join kind=leftouter (AzureDiagnostics
| where Category == "JobStreams"
| where StreamType_s == "Error"
| summarize TotalErrors = dcount(StreamType_s) by JobId_g, StreamType_s)
on $left. JobId_g == $right. JobId_g
| extend HasErrors = iff(StreamType_s == 'Error',true,false)
| project StartTime, EndTime, DurationSec,RunbookName,Status,HasErrors,TotalErrors,JobId_g
```
