# Microsoft Defender for Cloud Apps - Shadow IT Reporting

## Query Information

### Description

Use the below queries to reretrieve Defender for Cloud Apps - shadow discovery information. The first query represents the information as shown in the portal. The second query shows the information per user.

> Note that the data in the online portal is refreshed periodically, meaning that you might get different results when running the below queries.

#### References

#### Credits

Kim Oppalfens - @TheWMIGuy

### Microsoft Sentinel

MCAS Shadown Reporting details by Application

```kql
McasShadowItReporting
| where TimeGenerated > ago (90d)
| where StreamName == "Win10 Endpoint Users"
| summarize Totalbytes = sum(TotalBytes), UploadBytes = sum( UploadedBytes), DownloadBytes = sum(DownloadedBytes), Users = make_set(EnrichedUserName), Devices = make_set(MachineName), IPAddresses = make_set(IpAddress)  by AppName, AppScore
| extend TotalDevices = array_length(Devices)
| extend TotalIPAddresses = array_length(IPAddresses)
| extend Totalusers = array_length(Users)
| extend UploadMB = format_bytes(UploadBytes,0,"MB")
| extend TotalTraffic = format_bytes(Totalbytes,0,"MB")
| extend DownloadMB = format_bytes(DownloadBytes,0,"MB")
| project AppName,AppScore, TotalDevices, TotalIPAddresses, Totalusers, TotalTraffic, UploadMB, DownloadMB, IPAddresses, Devices, Users
```

MCAS Shadown Reporting details by User

```kql
McasShadowItReporting
| where TimeGenerated > ago (90d)
| where StreamName == "Win10 Endpoint Users"
| summarize Totalbytes = sum(TotalBytes), UploadBytes = sum( UploadedBytes), DownloadBytes = sum(DownloadedBytes), Users = make_set(EnrichedUserName), Devices = make_set(MachineName), IPAddresses = make_set(IpAddress) , Apps = make_set(AppName) by EnrichedUserName
| extend TotalDevices = array_length(Devices)
| extend TotalIPAddresses = array_length(IPAddresses)
| extend Totalusers = array_length(Users)
| extend TotalApps = array_length(Apps)
| extend UploadMB = format_bytes(UploadBytes,0,"MB")
| extend TotalTraffic = format_bytes(Totalbytes,0,"MB")
| extend DownloadMB = format_bytes(DownloadBytes,0,"MB")
| project EnrichedUserName, TotalDevices, TotalIPAddresses, Totalusers,TotalApps, TotalTraffic, UploadMB, DownloadMB, IPAddresses, Devices, Users, Apps

```
