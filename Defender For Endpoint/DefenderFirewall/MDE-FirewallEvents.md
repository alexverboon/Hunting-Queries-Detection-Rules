# TITLE

## Query Information

### Description

Get all filtering events done by the Windows filtering platform.
This includes any blocks done by Windows Firewall rules, but also blocks triggered by some 3rd party firewalls.

For firewall events to be displayed in Defender for Endpoint, you'll need to enable the audit policy, see Audit Filtering Platform connection. Firewall covers the following events

Within the Windows Event log the following events are created:

* 5025 - firewall service stopped
* 5031 - application blocked from accepting incoming connections on the network
* 5157 - blocked connection

#### References

- [Investigate devices in the Microsoft Defender for Endpoint Devices list](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/investigate-machines?view=o365-worldwide)
- [Audit Filtering Platform Connection](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection)

### Microsoft 365 Defender

Find Inbound and Outbound blocked events

```Kusto
DeviceEvents
| where ActionType in ("FirewallOutboundConnectionBlocked", "FirewallInboundConnectionBlocked", "FirewallInboundConnectionToAppBlocked")
| project DeviceName, DeviceId , Timestamp , InitiatingProcessFileName , InitiatingProcessParentFileName, RemoteIP, RemotePort, LocalIP, LocalPort
| summarize MachineCount=dcount(DeviceId) by RemoteIP
```
