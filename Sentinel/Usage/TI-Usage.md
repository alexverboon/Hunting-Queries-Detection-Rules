# TITLE

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)

![Status: Work in Progress](https://img.shields.io/badge/status-work--in--progress-yellow.svg)
![Status: In Progress](https://img.shields.io/badge/status-in--progress-yellow.svg)
![Status: Complete](https://img.shields.io/badge/status-complete-brightgreen.svg)
![Status: Done](https://img.shields.io/badge/status-done-green.svg)
![Status: Draft](https://img.shields.io/badge/status-draft-lightgrey.svg)
![Status: Planned](https://img.shields.io/badge/status-planned-blue.svg)
![Status: Pending](https://img.shields.io/badge/status-pending-orange.svg)
![Status: Pending Review](https://img.shields.io/badge/status-pending--review-blue.svg)
![Status: Under Review](https://img.shields.io/badge/status-under--review-blue.svg)
![Status: On Hold](https://img.shields.io/badge/status-on--hold-yellow.svg)
![Status: Blocked](https://img.shields.io/badge/status-blocked-red.svg)
![Status: Deprecated](https://img.shields.io/badge/status-deprecated-critical.svg)
![Status: Archived](https://img.shields.io/badge/status-archived-lightgrey.svg)
![Status: Maintenance](https://img.shields.io/badge/status-maintenance-orange.svg)
![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)
![Status: Beta](https://img.shields.io/badge/status-beta-blue.svg)
![Status: Preview](https://img.shields.io/badge/status-preview-blueviolet.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)
![Status: Experimental](https://img.shields.io/badge/status-experimental-red.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)




## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.003 | Credential Access: Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

### Description

DESCRIPTION

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
```

## Sentinel

```kql
```

Usage
| where DataType in ("ThreatIntelObjects", "ThreatIntelIndicators")
| extend Series = DataType
| summarize IngestedGB = sum(Quantity) / 1024.0 by bin(TimeGenerated, 1d), Series
| render timechart

union
(
    ThreatIntelObjects
    | summarize IngestedGB = sum(_BilledSize) / 1024.0 / 1024.0 / 1024.0 by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Objects"
),
(
    ThreatIntelIndicators
    | summarize IngestedGB = sum(_BilledSize) / 1024.0 / 1024.0 / 1024.0 by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Indicators"
)
| extend Series = strcat(SourceSystem, " | ", Type)
| project TimeGenerated, IngestedGB, Series
| render timechart




union
(
    ThreatIntelObjects
    | summarize Count = count() by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Objects"
),
(
    ThreatIntelIndicators
    | summarize Count = count() by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Indicators"
)
| extend Series = strcat(SourceSystem, " | ", Type)
| extend LogCount = log10(Count + 1.0)
| project TimeGenerated, LogCount, Series
| render timechart


union
(
    ThreatIntelObjects
    | summarize Count = count() by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Objects"
),
(
    ThreatIntelIndicators
    | summarize Count = count() by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Indicators"
)
| extend Series = strcat(SourceSystem, " | ", Type)
| extend LogCount = log10(Count + 1.0)
| project TimeGenerated, LogCount, Series
| render timechart


let Base =
    union
    (
        ThreatIntelObjects
        | summarize Count = count() by bin(TimeGenerated, 1d), SourceSystem
        | extend Type = "Objects"
    ),
    (
        ThreatIntelIndicators
        | summarize Count = count() by bin(TimeGenerated, 1d), SourceSystem
        | extend Type = "Indicators"
    )
    | extend Series = strcat(SourceSystem, " | ", Type)
    | summarize Count = sum(Count) by TimeGenerated, Series;
let MaxPerSeries =
    Base
    | summarize MaxCount = max(Count) by Series;
Base
| join kind=inner MaxPerSeries on Series
| extend Normalized = iff(MaxCount == 0, 0.0, todouble(Count) / todouble(MaxCount) * 100.0)
| project TimeGenerated, Normalized, Series
| render timechart


union
(
    ThreatIntelObjects
    | summarize Count = count() by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Objects"
),
(
    ThreatIntelIndicators
    | summarize Count = count() by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Indicators"
)
| extend Series = strcat(SourceSystem, " | ", Type)
| project TimeGenerated, Count, Series
| render timechart


Usage
| where DataType in ("ThreatIntelObjects", "ThreatIntelIndicators")
| extend Series = DataType
| summarize IngestedGB = sum(Quantity) / 1024.0 by bin(TimeGenerated, 1d), Series
| render timechart

union
(
    ThreatIntelObjects
    | summarize IngestedGB = sum(_BilledSize) / 1024.0 / 1024.0 / 1024.0 by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Objects"
),
(
    ThreatIntelIndicators
    | summarize IngestedGB = sum(_BilledSize) / 1024.0 / 1024.0 / 1024.0 by bin(TimeGenerated, 1d), SourceSystem
    | extend Type = "Indicators"
)
| extend Series = strcat(SourceSystem, " | ", Type)
| project TimeGenerated, IngestedGB, Series
| render timechart





ThreatIntelIndicators
| where TimeGenerated > ago(360d)
| where _IsBillable == true
| summarize 
    TotalVolumeGBLog = round(sum(_BilledSize / 1024 / 1024 / 1024), 2),
    Count = count() 
    by SourceSystem
    //| summarize round((sum(TotalVolumeGBLog)),2)
  

  
 Usage
| where TimeGenerated > ago (360d)
| where DataType == @"ThreatIntelIndicators"
| where IsBillable == true
| summarize TotalVolumeGBUsage = round(sum(Quantity/1024),2) by DataType