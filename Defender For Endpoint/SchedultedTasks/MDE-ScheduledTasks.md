---
title: "MDE - Scheduled Task Execution"

description: |
  Provides an overview of process activity associated with the Task Scheduler
  service, with a server-scoped execution query and a seven-day interval summary.
  Includes optional executable and account filters.

status: "InProgress"
queryType: "ThreatHunting"

risk: |
  Scheduled tasks can be abused for execution, persistence, or execution under
  privileged accounts. These queries identify candidate scheduler-related process
  activity, not malicious intent or proof of privilege escalation.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables"
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table"
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table"

mitre:
  - id: "T1053.005"
    name: "Scheduled Task/Job: Scheduled Task"
    url: "https://attack.mitre.org/techniques/T1053/005/"

dataSources:
  - table: "DeviceInfo"
    solution: "Microsoft Defender for Endpoint"
  - table: "DeviceProcessEvents"
    solution: "Microsoft Defender for Endpoint"

version: "2.0"
created: "2026-11-02"
lastModified: "2026-11-02"
---

![Status: In Progress](https://img.shields.io/badge/status-in%20progress-eab308.svg)
![Type: Threat Hunting](https://img.shields.io/badge/type-threat%20hunting-f97316.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# MDE - Scheduled Task Execution

## Query Information

### Description

Get an overview of scheduled tasks running in your environment through process
events whose initiating process is `svchost.exe` and whose initiating command
line contains the term `Schedule`.

The first variant selects the latest device record for each device, filters to
onboarded Windows servers, and left-joins matching process events. Servers
without matching process activity remain in the result. It has no explicit time
filter; the portal time range governs the available records.

The second variant examines the last seven days of matching process events
without restricting devices to servers. It calculates intervals between
consecutive events sharing device name, command line, and run-as account, then
summarizes observed timing and assigns an approximate schedule label. These
labels are heuristics, not the registered task's configured triggers.

### Risk

Scheduled tasks can be abused for execution, persistence, or execution under
privileged accounts. These queries identify candidate scheduler-related process
activity, not malicious intent or proof of privilege escalation. Legitimate
maintenance and software activity can match the same process characteristics.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [Defender XDR Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [DeviceInfo table schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)
- [DeviceProcessEvents table schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ |

Scheduled task abuse is associated with Execution, Persistence, and Privilege
Escalation. This mapping describes the mechanism being hunted, not a finding
that these tactics occurred.

### Data Sources

| Table | Solution |
| --- | --- |
| `DeviceInfo` | Microsoft Defender for Endpoint |
| `DeviceProcessEvents` | Microsoft Defender for Endpoint |

### False Positives and Tuning (Optional)

The retained optional filters restrict the first variant to `cmd.exe`,
`powershell.exe`, and `cscript.exe`, or exclude the account names `system`,
`local service`, and `network service`. The latter does not prove that the
remaining accounts are custom accounts. Apply filters to the first variant
only when that scope matches the investigation.

### Investigation Guidance (Optional)

Validate unusual commands and accounts against the device's registered task
definitions and expected maintenance activity. Check process context before
attributing activity to a task, and compare inferred intervals with configured
triggers rather than treating an inferred label as authoritative.

---

## KQL Query

### All scheduled Task executions on servers

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

#### Optional Filters

Retained filter snippets for the server execution variant:

```kql
// powershell, cmd and cscript only
| where FileName in ('cmd.exe','powershell.exe',"cscript.exe")

// only show custom accounts
| where TaskRunContext !in ('system','local service','network service')
```


### Scheduled Task Intervals

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
