# Defender External Attack Surface Management - Usage

## Query Information

### Description

Use the below queries to retrieve Defender External Attack Surface Management usage information. 

#### References

- [Data Connectors for Azure Log Analytics and Data Explorer Now in Public Preview](https://techcommunity.microsoft.com/t5/microsoft-defender-external/data-connectors-for-azure-log-analytics-and-data-explorer-now-in/ba-p/3776898)

### Microsoft Sentinel

EASM Billable Data

```kql
union withsource= _TableName Easm*
| where TimeGenerated > ago(30d)
| summarize
    Entries = count(), Size = sum(_BilledSize), GB = format_bytes(sum(_BilledSize),0,"GB") by _TableName
| project
    ['TableName'] = _TableName,
    ['Table Size'] = Size,
    ["GB"] = GB,
    ['Table Entries'] = Entries
```

Visualize EASM Table Usage over time

```kql
Usage
| where TimeGenerated > ago(30d)
| where DataType startswith "Easm"
| where StartTime >= startofday(ago(31d)) and EndTime < startofday(now())
| summarize BillableDataGB = sum(Quantity) / 1000. by bin(StartTime, 1d), DataType
| render columnchart   
```

Last entries written to EASM Tables

```kql
union withsource= _TableName Easm*
| where TimeGenerated > ago(90d)
| summarize arg_max(TimeGenerated,*) by _TableName
| project _TableName, TimeGenerated
```
