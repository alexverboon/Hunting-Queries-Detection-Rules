# WDAC Recommended Block List

## Query Information

### Description

Use the below query to identify processes that are on Microsoft's recommended WDAC block list

#### References

- [WDAC block list](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

### Microsoft 365 Defender

Identify processes that are on the WDAC recommended block list

```kql
let wdacblock = (externaldata(lolbin: string)
    [@"https://raw.githubusercontent.com/alexverboon/Hunting-Queries-Detection-Rules/main/ExternalData/wdacblockrules.txt"] 
    with (format="txt", ignoreFirstRecord=true));
DeviceProcessEvents 
| where FileName in (wdacblock) or InitiatingProcessFileName in (wdacblock)
```

Another approach shared by [Kim Oppalfens](https://twitter.com/TheWMIGuy)
let wdacblock = (externaldata(lolbin: string)
    [@"https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md"]
    with (format="txt", ignoreFirstRecord=true));
wdacblock
| where lolbin has '<Deny ID="ID_DENY_'
| extend lolbinxml = parse_xml(lolbin)
