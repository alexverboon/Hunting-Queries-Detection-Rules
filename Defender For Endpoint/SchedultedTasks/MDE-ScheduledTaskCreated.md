---
title: "Scheduled Task Creation Details"

description: |
  Lists scheduled task creation events and extracts the task name, subject user,
  trigger types, executable command, and arguments from AdditionalFields.
  Retains the parsed triggers and actions for threat hunting.

status: "Draft"
queryType: "ThreatHunting"

risk: |
  Windows scheduled tasks can support execution, persistence, or execution under
  a privileged account. Task creation alone does not establish malicious intent,
  successful execution, or privilege escalation.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables"
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table"

mitre:
  - id: "T1053.005"
    name: "Scheduled Task/Job: Scheduled Task"
    url: "https://attack.mitre.org/techniques/T1053/005/"

dataSources:
  - table: "DeviceEvents"
    solution: "Microsoft Defender for Endpoint"

version: "1.0"
created: "2026-11-02"
lastModified: "2026-11-02"
---

![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg)
![Type: Threat Hunting](https://img.shields.io/badge/type-threat%20hunting-f97316.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Scheduled Task Creation Details

## Query Information

### Description

Lists `DeviceEvents` records with `ActionType == "ScheduledTaskCreated"` in
Microsoft Defender XDR Advanced Hunting. Parses `AdditionalFields` and its
`TaskContent` value to extract the task name, subject user, trigger types, and
the command and arguments of an `Exec` action. Results include the event time,
device name, and parsed triggers and actions, ordered newest first.

The query has no explicit time filter; use the Advanced Hunting time-range
selector to scope the hunt. It lists creation events, not an inventory of
currently registered tasks or proof that a task executed.

### Risk

Windows scheduled tasks can support execution, persistence, or execution under
a privileged account. Task creation alone does not establish malicious intent,
successful execution, or privilege escalation. Review the task's purpose,
command, arguments, and account context before assessing risk.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [Defender XDR Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [DeviceEvents table schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ |

This behavior supports hunting for scheduled task abuse associated with
Execution, Persistence, and Privilege Escalation. The mapping describes possible
abuse of the observed mechanism, not a conclusion that any tactic occurred.

### Data Sources

| Table | Solution |
| --- | --- |
| `DeviceEvents` | Microsoft Defender for Endpoint |

### False Positives and Tuning (Optional)

Legitimate administration and software can create scheduled tasks. This query
does not distinguish authorized tasks from abuse. Validate expected tasks with
device owners before considering environment-specific exclusions.

### Investigation Guidance (Optional)

- Review the command, arguments, trigger details, subject user, and device
  context for consistency with the task's expected purpose.
- Inspect the original event payload when extracted values are empty or the
  action structure differs from the query's assumptions.
- Correlate with process activity and the registered task definition to establish
  whether execution occurred and which account the task runs as. The extracted
  subject user alone does not establish the task's execution identity.

---

## KQL Query

```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| extend AF = parse_json(AdditionalFields)
| extend TaskContent = parse_json(tostring(AF.TaskContent))
| extend
    TaskName = tostring(AF.TaskName),
    SubjectUserName = tostring(AF.SubjectUserName),
    TaskTriggers = TaskContent["Triggers"],
    TaskActions = TaskContent["Actions"]
| extend
    TaskTriggerType = strcat_array(bag_keys(TaskTriggers), ", "),
    TaskCommand = tostring(TaskActions["Exec"]["Command"]),
    TaskArguments = tostring(TaskActions["Exec"]["Arguments"])
| project
    Timestamp,
    DeviceName,
    SubjectUserName,
    TaskName,
    TaskTriggerType,
    TaskCommand,
    TaskArguments,
    TaskTriggers,
    TaskActions
| order by Timestamp desc
```
