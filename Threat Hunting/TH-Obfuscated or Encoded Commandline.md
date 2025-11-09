# Detection of obfuscated or encoded command lines in process events

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Work in Progress](https://img.shields.io/badge/status-work--in--progress-yellow.svg)

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                                                        | Link                                                        |
|--------------|--------------------------------------------------------------|-------------------------------------------------------------|
| T1047        | Windows Management Instrumentation                           | https://attack.mitre.org/techniques/T1047/                  |
| T1059.001    | Command and Scripting Interpreter: PowerShell                | https://attack.mitre.org/techniques/T1059/001/              |
| T1218        | System Binary Proxy Execution                                | https://attack.mitre.org/techniques/T1218/                  |
| T1027        | Obfuscated Files or Information                              | https://attack.mitre.org/techniques/T1027/                  |

### Description

This KQL query detects obfuscated or encoded command lines in process events by flagging non-ASCII characters, superscript Unicode, and Base64-like sequences. It extracts suspicious segments, attempts to decode Base64 candidates (preferring UTF-8 then falling back to UTF-16LE), and classifies obfuscation types to aid triage and investigation.

#### References

- [Bypassing Detections with Command-Line Obfuscation](https://www.wietzebeukema.nl/blog/bypassing-detections-with-command-line-obfuscation)
- [Windows Command-Line Obfuscation](https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation)

### Author

- **Alex Verboon**

## Defender XDR

```sql
// --- Regex definitions ---
let rxNonAscii    = @"[^\x20-\x7E]";                                       // Any character outside printable ASCII range
let rxSuperCap    = @"([\u02B0-\u02FF\u1D2C-\u1D7F\u2070-\u209F])";       // Superscript / modifier Unicode blocks (with capturing group)
let rxB64Presence = @"[A-Za-z0-9]{0,}[+/][A-Za-z0-9+/]{27,}={0,2}";       // Base64-like string (contains + or /, 28+ chars)
let rxB64Extract  = @"([A-Za-z0-9]{0,}[+/][A-Za-z0-9+/]{27,}={0,2})";     // Same as above but with capturing group for extract()
// --- Source events ---
DeviceProcessEvents
| where Timestamp >= ago(7d)                                               // Limit to last 7 days for performance
| where isnotempty(ProcessCommandLine)                                     // Only processes with a command line
| where InitiatingProcessFileName has_any ("cmd.exe","PowerShell.exe","notepad.exe") // Focus on common script interpreters
// --- Stage 1: quick pre-checks (cheap regex tests, no captures) ---
| extend HasNonAscii = ProcessCommandLine matches regex rxNonAscii         // Detect any non-ASCII characters
| extend HasSuper    = ProcessCommandLine matches regex rxSuperCap         // Detect superscript Unicode characters
| extend HasB64Quick = ProcessCommandLine matches regex rxB64Presence      // Detect Base64-like pattern presence
| where HasNonAscii or HasSuper or HasB64Quick                             // Only continue if any indicator is present
// --- Stage 2: extract actual suspicious content ---
| extend NonAsciiChars    = iif(HasNonAscii, extract_all(@"([^\x20-\x7E])", tostring(ProcessCommandLine)), dynamic([])) // Extract all non-ASCII chars
| extend SuperscriptChars = iif(HasSuper,    extract_all(rxSuperCap,           tostring(ProcessCommandLine)), dynamic([])) // Extract all superscripts
| extend Base64Candidate1 = iif(HasB64Quick, extract(rxB64Extract, 1, ProcessCommandLine), "")                            // Extract first Base64-like sequence
// --- Filter out benign cases (paths, files, PowerShell -File parameter) ---
| extend Base64Candidate1 = iif(
      Base64Candidate1 matches regex @"[\\/:\.]"                              // likely path or URL
      or ProcessCommandLine matches regex @"(?i)\b-File\b",                   // PowerShell script file parameter
      "", Base64Candidate1)
// --- Flags & counters ---
| extend EncodedFlag      = iif(isnotempty(Base64Candidate1), 1, 0)           // Flag if Base64 candidate found
| extend NonAsciiCount    = array_length(NonAsciiChars)                       // Count non-ASCII characters
| extend SuperScriptCount = iif(array_length(SuperscriptChars) > 0, 1, 0)     // Flag if superscript present
// --- Stage 3: decode Base64 candidate (UTF-8 first, fallback to UTF-16LE) ---
| extend DecodedUtf8 = iif(EncodedFlag==1, base64_decode_tostring(Base64Candidate1), "")  // Decode as UTF-8
| extend Bytes       = iif(EncodedFlag==1 and isempty(DecodedUtf8),                       // If not readable, decode to byte array
                           base64_decode_toarray(Base64Candidate1), dynamic(null))
| extend Len         = array_length(Bytes)                                                // Get byte array length
// --- Decode UTF-16LE manually if needed ---
| mv-apply idx = range(0, iif(isnotnull(Len) and Len >= 2, Len - 2, -1), 2) on (
    extend i = toint(idx)
    | where isnotnull(Bytes) and i + 1 < Len
    | extend lo = toint(Bytes[i]), hi = toint(Bytes[i + 1])                               // Low + high byte pair
    | extend cp = lo + 256*hi                                                             // Combine to code point
    | where cp != 0 and cp >= 32 and cp <= 126                                            // Keep printable ASCII only
    | summarize Codepoints = make_list(cp)
)
| extend DecodedUtf16 = iif(isnull(Codepoints), "", unicode_codepoints_to_string(Codepoints)) // Convert code points to string
| extend Decoded      = iif(isnotempty(DecodedUtf8), DecodedUtf8, DecodedUtf16)               // Prefer UTF-8, else UTF-16LE
// --- Stage 4: classify and label obfuscation types ---
| extend HasUnicode = NonAsciiCount > 0
| extend ObfTypes = set_difference(                                                        // Combine all triggered indicators
    pack_array(
      iif(EncodedFlag==1,       "EncodedCommand",    ""),                                   // Base64-like or encoded
      iif(SuperScriptCount > 0, "Superscript",       ""),                                   // Unicode superscripts
      iif(HasUnicode,           "Unicode/Non-ASCII", "")                                    // Other non-ASCII content
    ),
    pack_array("")
)
| extend ObfCount = array_length(ObfTypes)                                                 // Number of detected obfuscation signals
| where ObfCount > 0                                                                       // Keep only suspicious entries
// --- Final output ---
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName,                      // Basic identifiers
          ProcessCommandLine, Base64Candidate1, Decoded,                                   // Original + decoded command lines
          NonAsciiCount, SuperScriptCount, ObfTypes                                        // Detection details
```
