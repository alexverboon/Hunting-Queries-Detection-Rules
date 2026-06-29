# MDE - Scheduled Task Execution

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### Description

Get an overview of scheduled Tasks running in your environment...

#### References

- none

### Author

- **Alex Verboon**

## KQL

All scheduled Task executions on servers

```kql
let devicescope = (DeviceInfo
| summarize arg_max(TimeGenerated,*) by DeviceId
| where OnboardingStatus == 'Onboarded'
| where OSPlatform startswith "WindowsServer"
|  project DeviceName, DeviceId);
let runningtasks = (
DeviceProcessEvents
| where ActionType == @"ProcessCreated"
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessCommandLine has "Schedule"
| extend TaskRunContext = AccountName
| project
   Timestamp,
   DeviceName,
   DeviceId,
   TaskRunContext,
   AccountDomain,
   AccountSid,
   FileName,
   ProcessCommandLine,
   InitiatingProcessFileName,
   InitiatingProcessCommandLine,
   InitiatingProcessAccountName
| order by Timestamp desc);
devicescope
| join kind=leftouter (runningtasks)
on $left. DeviceId == $right. DeviceId
| project-away DeviceId1, DeviceId1, DeviceName1, DeviceId
```

// powershell, cmd and cscript only
| where FileName in ('cmd.exe','powershell.exe',"cscript.exe")

// only show custom accounts
| where TaskRunContext !in ('system','local service','network service')


Scheduled Task Intervals

```kql
let Lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessCommandLine has "Schedule"
//
// Process started by Task Scheduler
//
| extend RunAsAccount = strcat(AccountDomain, @"\", AccountName)
| project
    Timestamp,
    DeviceName,
    RunAsAccount,
    AccountSid,
    ExecutedFile = FileName,
    CommandLine = ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    ProcessId,
    InitiatingProcessId
//
// Calculate execution intervals
//
| sort by DeviceName asc, CommandLine asc, RunAsAccount asc, Timestamp asc
| serialize
| extend
    PreviousTimestamp = prev(Timestamp),
    PreviousDeviceName = prev(DeviceName),
    PreviousCommandLine = prev(CommandLine),
    PreviousRunAsAccount = prev(RunAsAccount)
| where DeviceName == PreviousDeviceName
    and CommandLine == PreviousCommandLine
    and RunAsAccount == PreviousRunAsAccount
| extend IntervalMinutes = datetime_diff("minute", Timestamp, PreviousTimestamp)
//
// Summarize schedule behavior
//
| summarize
    FirstSeen = min(PreviousTimestamp),
    LastSeen = max(Timestamp),
    ExecutionCount = count() + 1,
    MinIntervalMinutes = min(IntervalMinutes),
    AvgIntervalMinutes = round(avg(IntervalMinutes),2),
    MaxIntervalMinutes = max(IntervalMinutes),
    ObservedIntervals = make_set(IntervalMinutes,20)
    by
    DeviceName,
    RunAsAccount,
    AccountSid,
    ExecutedFile,
    CommandLine
//
// Human readable schedule guess
//
| extend InferredSchedulePattern = case(
    AvgIntervalMinutes between (0 .. 2), "Every few minutes",
    AvgIntervalMinutes between (14 .. 16), "Every ~15 minutes",
    AvgIntervalMinutes between (29 .. 31), "Every ~30 minutes",
    AvgIntervalMinutes between (55 .. 65), "Every ~1 hour",
    AvgIntervalMinutes between (115 .. 125), "Every ~2 hours",
    AvgIntervalMinutes between (350 .. 370), "Every ~6 hours",
    AvgIntervalMinutes between (710 .. 730), "Every ~12 hours",
    AvgIntervalMinutes between (1430 .. 1450), "Daily",
    AvgIntervalMinutes between (10000 .. 10120), "Weekly",
    strcat("~Every ", tostring(AvgIntervalMinutes), " minutes")
)
| project
    DeviceName,
    RunAsAccount,
    AccountSid,
    ExecutedFile,
    InferredSchedulePattern,
    ExecutionCount,
    FirstSeen,
    LastSeen,
    MinIntervalMinutes,
    AvgIntervalMinutes,
    MaxIntervalMinutes,
    ObservedIntervals,
    CommandLine
| order by ExecutionCount desc
```
