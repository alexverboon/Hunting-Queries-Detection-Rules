---
title: "Defender for Identity - LDAP Ping"

description: |
  This query reports Defender for Identity LDAP ping activity, extracting the
  source and destination devices, queried user/host/domain values, and result
  details. A second query summarizes source and destination pairs that queried
  more than five distinct usernames within a 15-minute interval.

status: "Draft"

queryType: "ThreatHunting"

risk: |
  Repeated LDAP ping requests for many usernames may indicate domain account
  enumeration, which can help an operator identify valid accounts for follow-on
  activity. Legitimate administrative or diagnostic activity can also generate
  LDAP queries; these results alone do not establish malicious intent.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityqueryevents-table"
  - "https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic"
  - "https://github.com/lkarlslund/ldapnomnom?"
  - "https://github.com/sensepost/UserEnum?"

mitre:
  - id: "T1087.002"
    name: "Account Discovery: Domain Account"
    url: "https://attack.mitre.org/techniques/T1087/002/"

dataSources:
  - table: "IdentityQueryEvents"
    solution: "Microsoft Defender XDR (Microsoft Defender for Identity)"

version: "1.0"
created: "2026-11-23"
lastModified: "2026-11-23"
---

![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg)
<!-- ![Status: In Progress](https://img.shields.io/badge/status-in%20progress-eab308.svg) -->
<!-- ![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg) -->
<!-- ![Status: Deprecated](https://img.shields.io/badge/status-deprecated-ef4444.svg) -->

<!-- QUERY TYPE: uncomment the badge matching the queryType above -->
<!-- ![Type: Detection](https://img.shields.io/badge/type-detection-ef4444.svg) -->
![Type: Threat Hunting](https://img.shields.io/badge/type-threat%20hunting-f97316.svg)
<!-- ![Type: Threat Intelligence](https://img.shields.io/badge/type-threat%20intelligence-a855f7.svg) -->
<!-- ![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg) -->
<!-- ![Type: Exposure Management](https://img.shields.io/badge/type-exposure%20management-8b5cf6.svg) -->
<!-- ![Type: Vulnerability](https://img.shields.io/badge/type-vulnerability-eab308.svg) -->

![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Defender for Identity - LDAP Ping

## Query Information

### Description

This query reports Defender for Identity LDAP ping activity, extracting the source and destination devices, queried user/host/domain values, and result details. A second query summarizes source and destination pairs that queried more than five distinct usernames within a 15-minute interval.

### Risk

Repeated LDAP ping requests for many usernames may indicate domain account enumeration, which can help an operator identify valid accounts for follow-on activity. Legitimate administrative or diagnostic activity can also generate LDAP queries; these results alone do not establish malicious intent.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [IdentityQueryEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityqueryevents-table)
- [Microsoft Defender for Identity classic security alerts](https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic)
- [ldapnomnom](https://github.com/lkarlslund/ldapnomnom?)
- [UserEnum](https://github.com/sensepost/UserEnum?)

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1087.002 | Account Discovery: Domain Account | https://attack.mitre.org/techniques/T1087/002/ |

### Data Sources

| Table | Solution |
| --- | --- |
| `IdentityQueryEvents` | Microsoft Defender XDR (Microsoft Defender for Identity) |

### False Positives and Tuning

Legitimate LDAP-based administrative, inventory, or diagnostic tools may query multiple usernames. Validate the source device and expected activity before treating results as suspicious. The second query's threshold is a hunting filter, not a confirmed-maliciousness threshold.

### Investigation Guidance

Review the source and destination devices, the queried usernames, and the success/failure counts. Correlate the activity with the source device's owner and other authentication or discovery activity in the same time period.

---

## KQL Query

```kql
// This query extracts the source, destination, LDAP filter, account referenced in the filter, and results.
IdentityQueryEvents
| where ActionType == "LDAP ping"
| extend AF = parse_json(AdditionalFields)
| extend
    SourceDevice = tostring(AF["FROM.DEVICE"]),
    DestinationDevice = tostring(AF["TO.DEVICE"]),
    ActorDevice = tostring(AF["ACTOR.DEVICE"]),
    LDAPFilter = tostring(AF.Filter),
    LDAPResultCode = tostring(AF.ResultCode),
    IsResultFound = tobool(AF.IsResultFound),
    LDAPCount = tolong(AF.Count)
| extend
    QueriedUser = extract(@"User=([^)]*)", 1, LDAPFilter),
    QueriedHost = extract(@"Host=([^)]*)", 1, LDAPFilter),
    QueriedDomain = extract(@"DnsDomain=([^)]*)", 1, LDAPFilter)
| project
    Timestamp,
    SourceDevice,
    DestinationDevice,
    QueriedUser,
    QueriedHost,
    QueriedDomain,
    LDAPResultCode,
    IsResultFound,
    LDAPCount,
    LDAPFilter
| order by Timestamp desc

// Now that we know AdditionalFields.Filter contains the requested username, we can look for sources testing many different usernames.
IdentityQueryEvents
| where ActionType == "LDAP ping"
| extend AF = parse_json(AdditionalFields)
| extend
    SourceDevice = tostring(AF["FROM.DEVICE"]),
    DestinationDevice = tostring(AF["TO.DEVICE"]),
    LDAPFilter = tostring(AF.Filter),
    IsResultFound = tobool(AF.IsResultFound)
| extend QueriedUser = extract(@"User=([^)]*)", 1, LDAPFilter)
| where isnotempty(QueriedUser)
| summarize
    TotalRequests = count(),
    UniqueUsers = dcount(QueriedUser),
    UsersQueried = make_set(QueriedUser, 100),
    SuccessfulResults = countif(IsResultFound == true),
    UnsuccessfulResults = countif(IsResultFound == false)
    by SourceDevice, DestinationDevice, bin(Timestamp, 15m)
| where UniqueUsers > 5
| order by UniqueUsers desc
```
