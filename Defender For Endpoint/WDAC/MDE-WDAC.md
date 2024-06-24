# Defender for Endpoint - WDAC

## Query Information

### Description

Advanced hunting queries for Windows Defender Application Control

#### References

 - [Querying Application Control events centrally using Advanced hunting](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/querying-application-control-events-centrally-using-advanced-hunting)


### Microsoft Defender

shows all the Windows Defender Application Control events generated from devices being monitored by Microsoft Defender for Endpoint

```kql
DeviceEvents
ActionType startswith "AppControl"
| summarize Machines=dcount(DeviceName) by ActionType
| order by Machines desc
```

// Microsoft recommended driver block rules
let wdacblockdrivers = (externaldata(lolbin: string)
    [@"https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md"]
    with (format="txt", ignoreFirstRecord=true));
wdacblockdrivers
| where lolbin has '<Deny ID="ID_DENY_'
| extend lolbinxml = parse_xml(lolbin)
| extend lolbin
| parse-kv lolbin as (FriendlyName:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| parse-kv lolbin as (Hash:string) with (pair_delimiter=' ', kv_delimiter='=', quote='"') 
| extend _FriendlyName_ = tostring(parse_json(tostring(lolbinxml.Deny)).["@FriendlyName"])
| project FriendlyName