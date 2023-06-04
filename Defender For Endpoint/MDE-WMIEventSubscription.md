# WMI Event Subscriptions

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1546.003 | Event Triggered Execution: Windows Management Instrumentation Event Subscription | https://attack.mitre.org/techniques/T1546/003/ |

### Description

DESCRIPTION

Use the below queries to find activities related to WMI Event subscriptions

#### References

- [Pen Test Lab - Persistence – WMI Event Subscription](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/)
- [Lateral Movement via WMI Event Subscription](https://www.ired.team/offensive-security/lateral-movement/lateral-movement-via-wmi-events)
- [Block persistence through WMI event subscription](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-persistence-through-wmi-event-subscription)

### Microsoft 365 Defender

  ASR Audit and Block events

```kql
DeviceEvents 
| where ActionType contains "AsrPersistenceThroughWmi"
```

Defender Alert

```kql
DeviceAlertEvents
| where Title contains "A WMI event filter was bound to a suspicious event consumer"
```

Using New-CimInstance cmdlet

```kql
let wmipersistencecommands = "New-CimInstance -Namespace root/subscription";
DeviceProcessEvents
| where ProcessCommandLine has (wmipersistencecommands)
```

```kql
  let pscommands = dynamic(["New-CimInstance"]);
  DeviceEvents
| where ActionType contains "PowerShellCommand"
| where AdditionalFields has_any (pscommands)
```

Using wmic

```kql
  DeviceProcessEvents
| where FileName contains "wmic"
| where ProcessCommandLine contains "root\\subscription" and ProcessCommandLine contains "CREATE"
```

Using mofcomp.exe

```kql
DeviceProcessEvents
| where FileName contains "mofcomp.exe"
```

