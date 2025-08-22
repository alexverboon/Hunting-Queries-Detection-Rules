# Defender XDR - Attack Disruption & Response

## Query Information

### Description

The ***DisruptionAndResponseEvents*** table in the advanced hunting contains information about automatic attack disruption events in Microsoft Defender XDR. These events include both block and policy application events related to triggered attack disruption policies, and automatic actions that were taken across related workloads.

#### References

- [DisruptionAndResponseEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-disruptionandresponseevents-table)
- [Defender XDR - What's new July 2025](https://learn.microsoft.com/en-us/defender-xdr/whats-new#july-2025)

### Author

- **Alex Verboon**

## Defender XDR

List compromised Accounts

```kql
DisruptionAndResponseEvents
| where isnotempty( CompromisedAccountCount)
```

Show Policies applied

```kql
DisruptionAndResponseEvents
| distinct PolicyName
```

Show unique ActionTypes

```kql
DisruptionAndResponseEvents
| distinct ActionType
```
