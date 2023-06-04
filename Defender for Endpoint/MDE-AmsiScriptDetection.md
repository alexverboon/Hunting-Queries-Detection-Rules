# Defender for Endpoint - AmsiScript Execution - Decode PowerShell commands

## Query Information

### Description

Run the below KQL query to decode powershell commands detected by AMSI

### References

### Microsoft 365 Defender

```Kusto
// Decode PowerShell AmsiScriptDetection's
DeviceEvents  
| where ActionType == @"AmsiScriptDetection"
| extend EncodedCommand = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, InitiatingProcessCommandLine)
| extend DecodedCommand = base64_decode_tostring(EncodedCommand)
| where isnotempty( DecodedCommand)
| project Timestamp, DeviceName, InitiatingProcessFileName,FileName,DecodedCommand 
```

