# Defender for Office - Email File Attachment File Extensions

## Query Information

### Description

Use the below queries to retireve information about email attachment formats / legacy formats. 

#### References

#### Credits

thanks to [Gianni](https://twitter.com/castello_johnny) for the dotcount method to identify the file extension

### Microsoft 365 Defender

Email attachment file extension overview

```kql
EmailEvents
| join EmailAttachmentInfo
on $left. NetworkMessageId ==  $right.NetworkMessageId
| extend DotCount = countof(FileName,".")
| extend FileExtension = strcat(".", split(FileName,".",DotCount)[0])
| where DeliveryAction != 'Delivered'
| where DotCount > 0
| project FileName, FileExtension, FileType, DotCount, EmailDirection, ThreatTypes
| summarize Out = countif(EmailDirection == 'Outbound'),In =  countif(EmailDirection == 'Inbound'), Intra = countif(EmailDirection == 'Intra-org'), Unknown = countif(EmailDirection == 'Unknown') by FileExtension
| sort by FileExtension
```

Email attachment file extension details

```kql
let FileExt = ".ISO";
EmailEvents
| join EmailAttachmentInfo
on $left. NetworkMessageId ==  $right.NetworkMessageId
| extend DotCount = countof(FileName,".")
| extend FileExtension = strcat(".", split(FileName,".",DotCount)[0])
| where FileExtension == FileExt
| where DeliveryAction != 'Delivered'
| where DotCount > 0
| project Timestamp, FileName, FileExtension, FileType, DotCount, EmailDirection, ThreatTypes, NetworkMessageId
```

legacy office file formats

```kql
let legacyofficeformats = dynamic([".doc",".dot",".ppt",".pot",".ppa","pps",".xls",".xla",".xlt",".xlw",".mdb"]);
EmailEvents
| join EmailAttachmentInfo
on $left. NetworkMessageId ==  $right.NetworkMessageId
| extend DotCount = countof(FileName,".")
| extend FileExtension = strcat(".", split(FileName,".",DotCount)[0])
| where FileExtension in (legacyofficeformats)
| where DeliveryAction != 'Delivered'
| where DotCount > 0
| project FileName, FileExtension, FileType, DotCount, EmailDirection, ThreatTypes
| summarize Out = countif(EmailDirection == 'Outbound'),In =  countif(EmailDirection == 'Inbound'), Intra = countif(EmailDirection == 'Intra-org'), Unknown = countif(EmailDirection == 'Unknown') by FileExtension
```

legacy office file formats

```kql
let legacyofficeformats = dynamic([".doc",".dot",".ppt",".pot",".ppa","pps",".xls",".xla",".xlt",".xlw",".mdb"]);
EmailEvents
| join EmailAttachmentInfo
on $left. NetworkMessageId ==  $right.NetworkMessageId
| extend DotCount = countof(FileName,".")
| extend FileExtension = strcat(".", split(FileName,".",DotCount)[0])
| where FileExtension in (legacyofficeformats)
| where DeliveryAction != 'Delivered'
| where DotCount > 0
| project Timestamp, FileName, FileExtension, FileType, DotCount, EmailDirection, ThreatTypes, NetworkMessageId
```

Email attachment file extension details

```kql
let legacyofficeformats = dynamic([".doc",".dot",".ppt",".pot",".ppa","pps",".xls",".xla",".xlt",".xlw",".mdb"]);
EmailEvents
| join EmailAttachmentInfo
on $left. NetworkMessageId ==  $right.NetworkMessageId
| extend DotCount = countof(FileName,".")
| extend FileExtension = strcat(".", split(FileName,".",DotCount)[0])
| where FileExtension in (legacyofficeformats)
| where DeliveryAction != 'Delivered'
| where DotCount > 0
| where EmailDirection == 'Inbound'
| project Timestamp, FileName, FileExtension, FileType, DotCount, EmailDirection, ThreatTypes, DeliveryAction, DeliveryLocation, DetectionMethods, EmailAction, ThreatNames, NetworkMessageId
| join kind=leftouter  EmailPostDeliveryEvents
on $left. NetworkMessageId ==  $right.NetworkMessageId
```

Email attachment file extension details

```kql
let legacyofficeformats = dynamic([".doc",".dot",".ppt",".pot",".ppa","pps",".xls",".xla",".xlt",".xlw",".mdb"]);
EmailEvents
| join EmailAttachmentInfo
on $left. NetworkMessageId ==  $right.NetworkMessageId
| extend DotCount = countof(FileName,".")
| extend FileExtension = strcat(".", split(FileName,".",DotCount)[0])
| where FileExtension in (legacyofficeformats)
| where DotCount > 0
| where EmailDirection == 'Inbound'
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderMailFromAddress, SenderFromDomain, FileName, FileExtension, FileType, DotCount, EmailDirection, ThreatTypes, DeliveryAction, DeliveryLocation, DetectionMethods, EmailAction, ThreatNames, NetworkMessageId
| summarize count() by DeliveryLocation
| render piechart 
```

file formats blocked configured in policy

```kql
let legacyofficeformats = dynamic([".ace",".ani",".app",".docm",".exe","jar",".reg",".scr",".vbe",".vbs"]);
EmailEvents
| join EmailAttachmentInfo
on $left. NetworkMessageId ==  $right.NetworkMessageId
| extend DotCount = countof(FileName,".")
| extend FileExtension = strcat(".", split(FileName,".",DotCount)[0])
| where FileExtension in (legacyofficeformats)
| where DotCount > 0
| where EmailDirection == 'Inbound'
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderMailFromAddress, SenderFromDomain, FileName, FileExtension, FileType, DotCount, EmailDirection, ThreatTypes, DeliveryAction, DeliveryLocation, DetectionMethods, EmailAction, ThreatNames, NetworkMessageId
// | summarize count() by DeliveryLocation
// | render piechart 
```

 legacy files on sharepoint , onedrive

```kql
let legacyofficeformats = dynamic([".doc",".dot",".ppt",".pot",".ppa","pps",".xls",".xla",".xlt",".xlw",".mdb"]);
CloudAppEvents
| where ActionType startswith "File"
| where ObjectType == @"File"
| where ActionType == @"FileUploaded" or ActionType == @"FileDownloaded"
| extend FileLocation = ActivityObjects[0].Name
| extend FileName = tostring(RawEventData.SourceFileName)
| extend DotCount = countof(FileName,".")
| extend FileExtension = strcat(".", split(FileName,".",DotCount)[0])| where FileExtension in (legacyofficeformats)
| summarize count() by FileExtension
```

Device File Creation events

```kql
let legacyofficeformats = dynamic(["doc","dot","ppt","pot","ppa","pps","xls","xla","xlt","xlw","mdb"]);
DeviceFileEvents
| extend FileInfo = parse_path(FolderPath)
| extend FileExtension = FileInfo.Extension
| extend Folder = FileInfo.DirectoryPath
| where FileExtension in (legacyofficeformats)
| where ActionType == @"FileCreated"
| project Timestamp, DeviceName,FileName,FileExtension,Folder, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName,InitiatingProcessAccountUpn, InitiatingProcessAccountName
```

// filter results - only office apps
// Device File Creation events

```kql
let legacyofficeformats = dynamic(["doc","dot","ppt","pot","ppa","pps","xls","xla","xlt","xlw","mdb"]);
let officeapps = dynamic(["WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE"]);
DeviceFileEvents
| extend FileInfo = parse_path(FolderPath)
| extend FileExtension = FileInfo.Extension
| extend Folder = FileInfo.DirectoryPath
| where FileExtension in (legacyofficeformats)
| where ActionType == @"FileCreated"
| project Timestamp, DeviceName,FileName,FileExtension,Folder, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName,InitiatingProcessAccountUpn, InitiatingProcessAccountName
| where InitiatingProcessVersionInfoProductName != @"Commvault"
| where InitiatingProcessFileName != @"System"
| where InitiatingProcessFileName != @"msiexec.exe"| where InitiatingProcessFileName != @"explorer.exe"
| where InitiatingProcessFileName in (officeapps)
```
