# Sentinel - Automation Rules and Playbook activitites

## Query Information

### Description

Use the below queries to gain insights into Sentinel Automation Rule and Playbook activities

#### References

- [Monitor the health of your automation rules and playbooks](https://learn.microsoft.com/en-us/azure/sentinel/monitor-automation-health)


### Microsoft Sentinel

```kql
SentinelHealth 
| where TimeGenerated > ago(90d)
| where SentinelResourceType == "Automation rule"
| mv-expand TriggeredPlaybooks = ExtendedProperties.TriggeredPlaybooks
| extend runId = tostring(TriggeredPlaybooks.RunId)
| join (AzureDiagnostics 
    | where OperationName == "Microsoft.Logic/workflows/workflowRunCompleted"
    | project
        resource_runId_s,
        playbookName = resource_workflowName_s,
        playbookRunStatus = status_s)
    on $left.runId == $right.resource_runId_s
| project
    RecordId,
    TimeGenerated,
    AutomationRuleName= SentinelResourceName,
    AutomationRuleStatus = Status,
    Description,
    workflowRunId = runId,
    playbookName,
    playbookRunStatus
```


```kql
SentinelHealth
| where OperationName == "Playbook was triggered"
```

```kql
SentinelHealth
| where OperationName == "Automation rule run"
```

```kql
SentinelHealth
| where OperationName == "Automation rule run"
```


