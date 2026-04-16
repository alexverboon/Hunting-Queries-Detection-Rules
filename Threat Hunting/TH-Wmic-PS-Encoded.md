# WMIC spawning PowerShell with encoded command

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                                                        | Link                                                        |
|--------------|--------------------------------------------------------------|-------------------------------------------------------------|
| T1047        | Windows Management Instrumentation                           | https://attack.mitre.org/techniques/T1047/                  |
| T1059.001    | Command and Scripting Interpreter: PowerShell                | https://attack.mitre.org/techniques/T1059/001/              |
| T1218        | System Binary Proxy Execution                                | https://attack.mitre.org/techniques/T1218/                  |
| T1027        | Obfuscated Files or Information                              | https://attack.mitre.org/techniques/T1027/                  |

### Description

Use the below query for detecting suspicious usage of WMIC that spawns a PowerShell process with an encoded command

Example

The below exmaple will execute wmic, spawn a powershell process and then run the following ***command Write-Output "WMIC benign test - safe"***

```powershell
wmic  process call create "powershell -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcATQBJAEMAIABiAGUAbgBpAGcAbgAgAHQAZQBzAHQAIAAtACAAcwBhAGYAZQAiAA=="
```

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
DeviceProcessEvents
| where FileName == @"WMIC.exe"
| where ProcessCommandLine has_any ("EncodedCommand","Enc")
| project Timestamp, DeviceName, InitiatingProcessFileName,ActionType, AccountName, ProcessCommandLine
| extend Encoded = extract(@"-(?:EncodedCommand|enc)\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| where isnotempty(Encoded)
| extend Decoded = base64_decode_tostring(Encoded) 
```
