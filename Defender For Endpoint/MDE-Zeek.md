# Microsoft Defender for Endpoint - Zeek

## Query Information

### Description

Use the below queries to retrieve additional network inforamtion from MDE devices.

#### References

- [Hunting for network signatures in Microsoft Defender for Endpoint](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-network-signatures-in-microsoft-defender-for/ba-p/3429520)

- [Enrich your advanced hunting experience using network layer signals from Zeek](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/enrich-your-advanced-hunting-experience-using-network-layer/ba-p/3794693)

- [New network-based detections and improved device discovery using Zeek](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/new-network-based-detections-and-improved-device-discovery-using/ba-p/3682111)

- [Zeek and Defender Endpoint](https://isc.sans.edu/diary/Zeek+and+Defender+Endpoint/30088/)

- [Tom Webb](https://isc.sans.edu/handler_list.html#tom-webb)

Zeek References

- [DNS](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/dns/main.zeek)
- [FTP](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ftp/main.zeek)
- [ssh](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ssh/main.zeek)
- [RDP](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/rdp/main.zeek)
- [ntlm](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ntlm/main.zeek)
- [smb](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/smb/main.zeek)
- [ssl](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ssl/main.zeek)
- [snmp](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/snmp/main.zeek)
- [http](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/http/main.zeek)
- [icmp](https://github.com/zeek/zeek/blob/master/scripts/base/packet-protocols/icmp/main.zeek)

### Microsoft 365 Defender

```kql
DeviceNetworkEvents
| where ActionType contains 'ConnectionInspected'
| distinct ActionType

```

look for rare user agents in the environment to identify potentially suspicious outbound web requests and cover the "T1071.001: (Application Layer Protocol) Web Protocols" technique.

```kql
// Identify rare User Agent strings used in http conversations
DeviceNetworkEvents
| where ActionType == 'HttpConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend direction = tostring(json.direction), user_agent = tostring(json.user_agent)
| where direction == 'Out'
| summarize Devices = dcount(DeviceId) by user_agent
| sort by Devices asc
```

Suppose you have identified a suspicious-looking user-agent named “TrickXYZ 1.0” and need to determine which user/process/commandline combination had initiated that connection.  Currently, the HttpConnectionInspected events, as with all Zeek-related action types, do not contain that information, so you must execute a follow-up query by joining with events from  ConnectionEstablished action type. Here’s an example of a follow-up query:

```kql
// Identify usage of a suspicious user agent
DeviceNetworkEvents
| where Timestamp > ago(1h) and ActionType == "HttpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend user_agent = tostring(json.user_agent)
| where user_agent == "TrickXYZ"
| project ActionType,AdditionalFields, LocalIP,LocalPort,RemoteIP,RemotePort, TimeKey = bin(Timestamp, 5m)
| join kind = inner (
DeviceNetworkEvents
| where Timestamp > ago(1h) and ActionType == "ConnectionSuccess"
| extend TimeKey = bin(Timestamp, 5m)) on LocalIP,RemoteIP,LocalPort,TimeKey
| project DeviceId, ActionType, AdditionalFields, LocalIP,LocalPort,RemoteIP,RemotePort , InitiatingProcessId,InitiatingProcessFileName,TimeKey

```

In another example, let’s look for file downloads from HTTP, particularly files of executable and compressed file extensions to cover the "T1105: Ingress tool transfer" technique:

```kql
// Detect file downloads
DeviceNetworkEvents
| where ActionType == 'HttpConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend direction= tostring(json.direction), user_agent=tostring(json.user_agent), uri=tostring(json.uri)
| where uri matches regex @"\.(?:dll|exe|zip|7z|ps1|ps|bat|sh)$"

```

Let’s look at a few advanced hunting examples using this action type. In the first example, you want to look for potentially infected devices trying to perform "T1110: Brute-Force" against remote servers using SSH as an initial step to “T1021.004: Lateral Movement - Remote Services: SSH”.

The query below will give you a list of Local/Remote IP combinations with at least 12 failed attempts (three failed authentications on four sessions) of SSH connections in the last hour. Feel free to use this example and adapt it to your needs.

```kql
// Detect potential bruteforce/dictionary attacks against SSH
DeviceNetworkEvents
| where ActionType == 'SshConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend direction=tostring(json.direction), auth_attempts = toint(json.auth_attempts), auth_success=tostring(json.auth_success)
| where auth_success=='false'
| where auth_attempts > 3
| summarize count() by LocalIP, RemoteIP
| where count_ > 4
| sort by count_ desc

```

In the next example, let’s suppose you are looking to identify potentially vulnerable SSH versions and detect potentially unauthorized client software being used to initiate SSH connections and operating systems that are hosting SSH server services in your environment:

```kql
// Identify Server/Client pairs being used for SSH connections
DeviceNetworkEvents
| where  ActionType == "SshConnectionInspected"
| extend json = todynamic(AdditionalFields)
| project Server = tostring(json.server),Client = tostring(json.client)
| distinct Server ,Client

```

In the first example, you wish to look for potential data leakage via ICMP to cover the "T1048: Exfiltration Over Alternative Protocol" or "T1041: Exfiltration Over C2 Channel" techniques. The idea is to look for outbound connections and check the payload bytes a device sends in a given timeframe. We will parse the direction, orig_bytes, and duration fields and look for conversations over 100 seconds where more than 500,000 were sent. The numbers are used as an example and do not necessarily indicate malicious activity. Usually, you will see the download and upload are almost equal for ICMP traffic because most devices generate “ICMP reply” with the same payload that was observed on the “ICMP echo” request.

```kql
// search for high upload over ICMP
DeviceNetworkEvents
| where ActionType == "IcmpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend Upload = tolong(json['orig_bytes']), Download = tolong(json['resp_bytes']), Direction = tostring(json.direction), Duration = tolong(json.duration)
| where Direction == "Out" and Duration > 100 and Upload > 500000
| top 10 by Upload
| project RemoteIP, LocalIP, Upload = format_bytes(Upload, 2, "MB"), Download = format_bytes(Download, 2, "MB"),Direction,Duration,Timestamp,DeviceId,DeviceName

```

In the last example, you wish to create another hunting query that helps you detect potential Ping sweep activities in your environment to cover the "T1018: Remote System Discovery" and "T1595: Active Scanning" techniques. The query will look for outbound ICMP traffic to internal IP addresses, create an array of the targeted IPs reached from the same source IP, and display them if the same source IP has pinged more than 5 IP Addresses within a 10-minute time window.

```Kkql
// Search for ping scans
DeviceNetworkEvents
| where ActionType == "IcmpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend Direction = json.direction
| where Direction == "Out" and ipv4_is_private(RemoteIP)
| summarize IpsList = make_set(RemoteIP) by DeviceId, bin(Timestamp, 10m)
| where array_length(IpsList) > 5
```

Identifying the origin process of ICMP traffic can be challenging as ICMP is an IP-Layer protocol. Still, we can use some OS-level indications to narrow down our search. We can use the following query to identify which process-loaded network, or even ICMP-specific, binaries:

```kql
DeviceImageLoadEvents
| where FileName =~ "icmp.dll" or FileName =~ "Iphlpapi.dll"
```

```kql
DeviceNetworkEvents
| where ActionType == 'HttpConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend direction= tostring(json.direction), user_agent=tostring(json.user_agent), uri=tostring(json.uri)
| where uri matches regex @"\.(?:dll|exe|zip|7z|ps1|ps|bat|sh)$"
| extend DotCount = countof(uri,".")
| extend FileExtension = strcat(".", split(uri,".",DotCount)[0])
| summarize count() by uri
```

A simple query to get just all POST methods and get a feel for how it works.

```kql
DeviceNetworkEvents
| where ActionType == 'HttpConnectionInspected' and AdditionalFields contains "POST"
```

A device named ClickHappy got a phishing email that went to IP 1.2.3.4, and the web form is an HTTP post. The user was off the corporate network then, so you do not have your typical network monitoring stack to rely on. You can query Defender if they sent a POST to the website.

```kql
DeviceNetworkEvents
| where ActionType == 'HttpConnectionInspected' and AdditionalFields contains "POST" and DeviceName contains "Clickhappy" and RemoteIP == "1.2.3.4"
```

If you got a result for the query, the user likely fell for the attack.

The additional fields are in JSON; to search very specifically, use this format. In this case, Im looking for user agent "gSOAP/2.7".

```kql
DeviceNetworkEvents
| where Timestamp > ago(1h) and ActionType == "HttpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend user_agent = tostring(json.user_agent)
| where user_agent == "gSOAP/2.7"
```

There are many great hunts people are already using for Zeek data with SecurityOnion, and all of these still apply to this data set too. You can also pull in external data and run queries against that data. In this case, we are grabbing a data feed with a list of malicious user agents and querying the last 5 days of data.

```kql
let bad_useragent = (externaldata(useragent_list: string)
[@"https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"]
with (format= "txt"))
| project useragent_list;
bad_useragent
| join (DeviceNetworkEvents
| where Timestamp > ago(5d) and ActionType == "HttpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend user_agent = tostring(json.user_agent)
)on $left.useragent_list == $right.user_agent
```

To query DNS names, use the below query.

```kql
DeviceNetworkEvents
| where ActionType == 'DnsConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend query = tostring(json.query)
| where query == "download.windowsupdate.com"
```

Below is an example with InboundInternetScanInspected to identify systems that are exposed to the internet and have connections with bad IPs

```kql
let IP_Indicators = (
(ThreatIntelligenceIndicator
| where TimeGenerated >= ago(90d) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
| where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80" and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127.")
| distinct TI_ipEntity, Description, ThreatType, SourceSystem
);
DeviceNetworkEvents
| where ActionType == "InboundInternetScanInspected"
| project TimeGenerated, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType
| extend geoinfo = geo_info_from_ip_address(LocalIP)
| extend country = tostring(geoinfo.country)
| extend city = tostring(geoinfo.city)
| extend state = tostring(geoinfo.state)
| project-away geoinfo
| join IP_Indicators on $left. LocalIP == $right. TI_ipEntity
```

Now that we know there are Bad IPs, let take a look at other network connections with these IPs

```kql
let IP_Indicators = (
(ThreatIntelligenceIndicator
| where TimeGenerated >= ago(90d) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
| where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80" and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127.")
| distinct TI_ipEntity, Description, ThreatType, SourceSystem
);
let BadIPs =  (
DeviceNetworkEvents
| where ActionType == "InboundInternetScanInspected"
| project TimeGenerated, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType
| extend geoinfo = geo_info_from_ip_address(LocalIP)
| extend country = tostring(geoinfo.country)
| extend city = tostring(geoinfo.city)
| extend state = tostring(geoinfo.state)
| project-away geoinfo
| join IP_Indicators on $left. LocalIP == $right. TI_ipEntity
| distinct TI_ipEntity);
DeviceNetworkEvents
| where RemoteIP in (BadIPs)
```

```kql
let IP_Indicators = (
(ThreatIntelligenceIndicator
| where TimeGenerated >= ago(90d) and ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| where Active == true
| where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempty(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
| extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinationIP)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP), NetworkSourceIP, TI_ipEntity)
| extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAddress), EmailSourceIpAddress, TI_ipEntity)
| where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80" and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127.")
| distinct TI_ipEntity, Description, ThreatType, SourceSystem
);
DeviceNetworkEvents
| where ActionType == "IcmpConnectionInspected"
| where TimeGenerated > ago(180d)
| extend json = todynamic(AdditionalFields)
| extend direction= tostring(json.direction), user_agent=tostring(json.user_agent), uri=tostring(json.uri), conn_state = tostring(json.conn_state)
| join IP_Indicators on $left. RemoteIP == $right. TI_ipEntity
```kql


More FTP connection parsing

```kql
DeviceNetworkEvents
| where ActionType == "FtpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend command = tostring(json.command)
| extend reply_code = tostring(json.reply_code)
| extend reply_msg = tostring(json.reply_msg)
| extend direction = tostring(json.direction)
| extend user = tostring(json.user)
| extend arg = tostring(json.arg)
| extend cwd = tostring(json.cwd)
```

SMTP

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where ActionType == "SmtpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend from = tostring(json.from)
| extend direction= tostring(json.direction)
| extend helo = tostring(json.helo)
| extend last_reply = tostring(json.last_reply)
| extend mailfrom = tostring(json.mailfrom)
| extend rcptto= tostring(json.rcptto)
| extend subject = tostring(json.subject)
| extend tls = tostring(json.tls)
```


```kql
let lookback = 90d;
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where ActionType == "SmtpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend from = tostring(json.from)
| extend direction= tostring(json.direction)
| extend helo = tostring(json.helo)
| extend last_reply = tostring(json.last_reply)
| extend mailfrom = tostring(json.mailfrom)
| extend rcptto= tostring(json.rcptto)
| extend subject = tostring(json.subject)
| extend tls = tostring(json.tls)
| extend rcpttolenght = array_length(parse_json(rcptto))
| extend fromemail = extract(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b",0,tostring(from))
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, direction, from, mailfrom,fromemail, helo, last_reply, tls, rcptto, rcpttolenght, subject
```



```kql

DeviceNetworkEvents
| where ActionType == 'DnsConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend query = tostring(json.query)
| extend answers = tostring(json.answers)
| extend qtype_name_ = tostring(AdditionalFields.qtype_name)
| extend direction_ = tostring(AdditionalFields.direction)
| mv-expand todynamic(answers)
| extend TLD = tostring(split(extract(@"\.([a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2})$",0,query,typeof(string)),".")[1])
| extend aDomain = extract(@"[^.]+\.[^.]+$",0,tostring(answers))
| extend qDomain = extract(@"[^.]+\.[^.]+$",0,tostring(query))
| project TimeGenerated, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol, answers, query, qtype_name_, aDomain, qDomain
```


DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where ActionType == 'DnsConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend query = tostring(json.query)
| extend answers = tostring(json.answers)
| extend qtype_name_ = tostring(AdditionalFields.qtype_name)
| extend direction_ = tostring(AdditionalFields.direction)
| extend ts_ = tostring(AdditionalFields.ts)
| extend trans_id_ = tostring(AdditionalFields.trans_id)
| mv-expand todynamic(answers)
| extend TLD = tostring(split(extract(@"\.([a-zA-Z]{2,}|[a-zA-Z]{2}\.[a-zA-Z]{2})$",0,query,typeof(string)),".")[1])
| extend aDomain = extract(@"[^.]+\.[^.]+$",0,tostring(answers))
| extend qDomain = extract(@"[^.]+\.[^.]+$",0,tostring(query))
| extend NameLenght = strlen(qDomain)
| project TimeGenerated, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol, answers, query, qtype_name_, aDomain, qDomain, trans_id_,ts_, NameLenght
//| summarize count() by qtype_name_
////| where qtype_name_ == "TXT"