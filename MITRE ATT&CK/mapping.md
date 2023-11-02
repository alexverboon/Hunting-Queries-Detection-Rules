# MITRE ATT&CK Mapping

This page includes the mapping of KQL queries to the [MITRE ATT&CK](https://attack.mitre.org/) framework. The framework is a knowledge base of adversary tactics and techniques based on real-world observations.

This section only includes references to queries that can be mapped in the MITRE ATT&CK Framework. Reconnaissance and Resource Development are out of scope.

## Initial Access

| Technique ID | Title    | Query    |
| ---  | --- | --- |

## Execution

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1546.003 | Windows Management Instrumentation Event Subscription |[WMI Event Subscriptions](../Defender%20For%20Endpoint/MDE-WMIEventSubscription.md) |

## Persistence

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1136.001 |  Create Account: Local Account | [Create Local Account](../Defender%20For%20Endpoint/MDE-LocalAccountCreated.md)  |

## Privilege Escalation

| Technique ID | Title    | Query    |
| ---  | --- | --- |

## Defense Evasion

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1564.004 | Hide Artifacts: NTFS File Attributes | [NTFS File Attributes - alternate data streams](../Defender%20For%20Endpoint/MDE-NTFS%20File%20Attributes%20-%20alternate%20data%20streams.md) |
| T1484.001 | Domain Policy Modification: Group Policy Modification | [AD Group Policy changes on devices](../Defender%20For%20Endpoint/MDE-GroupPolicyModificationEvents.md) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Defender Antivirus Exclusions](../Defender%20For%20Endpoint/MDE-DefenderAntivirusExclusions.md) |
| T1562.004 | Impair Defenses:  Disable or Modify System Firewall | [Defender Firewall Configurations](../Defender%20For%20Endpoint/DefenderFirewall//MDE-FirewallConfiguration.md) |

## Credential Access

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1110.003 | Brute Force: Password Spraying | [password spray attacks](/Defender%20365/MD365-PasswordSprayAttacks.md) |

## Discovery

| Technique ID | Title    | Query    |
| ---  | --- | --- |

## Lateral Movement

| Technique ID | Title    | Query    |
| ---  | --- | --- |

## Collection

| Technique ID | Title    | Query    |
| ---  | --- | --- |

## Command and Control

| Technique ID | Title    | Query    |
| ---  | --- | --- |

## Exfiltration

| Technique ID | Title    | Query    |
| ---  | --- | --- |

## Impact

| Technique ID | Title    | Query    |
| ---  | --- | --- |
