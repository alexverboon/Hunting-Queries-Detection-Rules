# Defender for Endpoint - Potential suspicious TCP Flags

## Query Information

### Description

This query tries to detect network traffic with potentially malicious or uncommon TCP Flags

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
let FlagReference = datatable(TcpFlagDecimal:string, Comment:string)
[
    6,  "SYN + RST (invalid, often scanning)",
    7,  "FIN + SYN + RST (highly abnormal)",
    19, "FIN + PSH + SYN (malformed scan)",
    27, "FIN + PSH + SYN + URG (malformed, stealth scan)",
    30, "FIN + PSH + RST + SYN (Xmas variant)",
    31, "FIN + PSH + RST + SYN + URG (classic Xmas scan)",
    63, "All flags set including ECE/CWR (invalid combination)"
];
let suspiciousflags = dynamic(["6","7","19","27","30","31","63"]);
DeviceNetworkEvents
| extend info = parse_json( AdditionalFields)
| extend TcpFlags = tostring(parse_json(info)["Tcp Flags"])
| extend direction =  info["direction"]
| where direction has "In"
| extend Geo_IP = tostring(geo_info_from_ip_address(RemoteIP).country)
| extend IsPrivate = ipv4_is_private(RemoteIP)
| project TimeGenerated, DeviceName, LocalIP, LocalPort, RemoteIP, IsPrivate, RemotePort, Geo_IP, TcpFlags, ActionType
//| where IsPrivate == "0"
| where TcpFlags has_any (suspiciousflags)
| lookup kind=leftouter FlagReference on $left.TcpFlags == $right.TcpFlagDecimal

```
