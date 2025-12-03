# Defender for Office 365 - Anti-spam outbound policy - AutoForwardingMode

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1114.003 | Email Collection: Email Forwarding Rule  | https://attack.mitre.org/techniques/T1114/003/ |

### Description

This KQL query identifies changes to the AutoForwardingMode setting in Defender for Office 365 outbound anti-spam policies. It extracts the configured value (Automatic, On, Off) and adds a readable description explaining whether automatic external forwarding is allowed, blocked, or system-controlled.

#### References

- [Control automatic external email forwarding from cloud mailboxes](https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding)
- [Alert classification for suspicious email forwarding activity](https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-email-forwarding?utm_source=chatgpt.com)

### Author

- **Alex Verboon**

## Defender XDR

```kql
OfficeActivity
| where Operation == @"Set-HostedOutboundSpamFilterPolicy"
| mv-expand parse_json(Parameters)
| extend Setting = parse_json(Parameters)["Name"]
| extend Configuration = parse_json(Parameters)["Value"]
| where Setting == "AutoForwardingMode"
| extend Description = case(
        Configuration == "Automatic", "System-controlled: Default value. Same as Off — forwarding is disabled.",
        Configuration == "On", "Forwarding is enabled: Automatic external forwarding is allowed and not restricted.",
        Configuration == "Off", "Forwarding is disabled: Automatic external forwarding is blocked and results in an NDR to the sender.",
        "Unknown"
    )
| project TimeGenerated, Setting, Configuration, Description
```

```kql
CloudAppEvents
| where ObjectName == "Set-HostedOutboundSpamFilterPolicy"
| mv-expand parse_json(ActivityObjects)
| where ActivityObjects.Name == 'AutoForwardingMode'
| extend Setting = tostring(ActivityObjects.Name)
| extend Configuration = tostring(ActivityObjects.Value)
| extend Description = case(
        Configuration == "Automatic", "System-controlled: Default value. Same as Off — forwarding is disabled.",
        Configuration == "On", "Forwarding is enabled: Automatic external forwarding is allowed and not restricted.",
        Configuration == "Off", "Forwarding is disabled: Automatic external forwarding is blocked and results in an NDR to the sender.",
        "Unknown"
    )
| project TimeGenerated, Setting,Configuration,Description
```
