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
let rxNonAscii        = @"[^\x20-\x7E]";                                      // Any char outside printable ASCII
let rxSuperCap        = @"([\u02B0-\u02FF\u1D2C-\u1D7F\u2070-\u209F])";       // Superscript / modifier blocks
let rxDashVariants    = @"([\u2010-\u2015\u2212\uFE58\uFE63\uFF0D])";         // En/Em/figure/minus etc. dash look-alikes
// Base64 detectors: standard + URL-safe, length threshold tunable (20/24/28)
let rxB64Presence     = @"[A-Za-z0-9+/]{20,}={0,2}";                          // standard Base64 presence
let rxB64Extract      = @"(^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{20,}={0,2})([^A-Za-z0-9+/=]|$)"; // capture group 2
let rxB64UrlPresence  = @"[A-Za-z0-9_-]{20,}={0,2}";                          // URL-safe Base64 presence
let rxB64UrlExtract   = @"(^|[^A-Za-z0-9\-_=])([A-Za-z0-9_-]{20,}={0,2})([^A-Za-z0-9\-_=]|$)"; // capture group 2
// --- Source events ---
DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where isnotempty(ProcessCommandLine)
| where InitiatingProcessFileName has_any ("cmd.exe","PowerShell.exe","notepad.exe")
// --- Stage 1: quick pre-checks ---
| extend HasNonAscii = ProcessCommandLine matches regex rxNonAscii
| extend HasSuper    = ProcessCommandLine matches regex rxSuperCap
| extend HasDashVar  = ProcessCommandLine matches regex rxDashVariants
| extend HasB64Quick = (ProcessCommandLine matches regex rxB64Presence)
                    or (ProcessCommandLine matches regex rxB64UrlPresence)
| where HasNonAscii or HasSuper or HasDashVar or HasB64Quick
// --- Stage 2: extract suspicious content ---
| extend NonAsciiChars    = iif(HasNonAscii, extract_all(@"([^\x20-\x7E])", tostring(ProcessCommandLine)), dynamic([]))
| extend SuperscriptChars = iif(HasSuper,    extract_all(rxSuperCap,           tostring(ProcessCommandLine)), dynamic([]))
| extend DashVarChars     = iif(HasDashVar,  extract_all(rxDashVariants,       tostring(ProcessCommandLine)), dynamic([]))
// Take group 2 because patterns are (prefix)(Base64)(suffix)
| extend Base64Candidate1 = iif(HasB64Quick,
      coalesce(
        extract(rxB64Extract,     2, ProcessCommandLine),
        extract(rxB64UrlExtract,  2, ProcessCommandLine),
        ""
      ),
      ""
)
// --- Filter out benign cases (paths, URLs, or PowerShell -File) ---
| extend Base64Candidate1 = iif(
      Base64Candidate1 matches regex @"[\\/:\.]"
      or ProcessCommandLine matches regex @"(?i)\b-File\b",
      "",
      Base64Candidate1
    )
// --- Flags & counters ---
| extend EncodedFlag       = iif(isnotempty(Base64Candidate1), 1, 0)
| extend NonAsciiCount     = array_length(NonAsciiChars)
| extend SuperScriptCount  = iif(array_length(SuperscriptChars) > 0, 1, 0)
| extend DashVariantCount  = array_length(DashVarChars)
// --- Normalize Base64 for decoding (handle URL-safe - and _ ) ---
| extend B64Std = iif(EncodedFlag == 1,
                      replace_string(replace_string(Base64Candidate1, "-", "+"), "_", "/"),
                     "")
// --- Stage 3: decode Base64 (UTF-8 first, fallback to UTF-16LE) ---
| extend DecodedUtf8 = iif(EncodedFlag==1, base64_decode_tostring(B64Std), "")
| extend Bytes       = iif(EncodedFlag==1 and isempty(DecodedUtf8),
                           base64_decode_toarray(B64Std),
                           dynamic(null))
| extend Len         = array_length(Bytes)
// --- UTF-16LE fallback (manual) ---
| mv-apply idx = range(0, iif(isnotnull(Len) and Len >= 2, Len - 2, -1), 2) on (
    extend i = toint(idx)
    | where isnotnull(Bytes) and i + 1 < Len
    | extend lo = toint(Bytes[i]), hi = toint(Bytes[i + 1])
    | extend cp = lo + 256*hi
    | where cp != 0 and cp >= 32 and cp <= 126
    | summarize Codepoints = make_list(cp)
)
| extend DecodedUtf16 = iif(isnull(Codepoints), "", unicode_codepoints_to_string(Codepoints))
| extend Decoded      = iif(isnotempty(DecodedUtf8), DecodedUtf8, DecodedUtf16)
// --- Stage 4: classify & label obfuscation types ---
| extend HasUnicode = NonAsciiCount > 0
| extend ObfTypes = set_difference(
    pack_array(
      iif(EncodedFlag==1,        "EncodedCommand",    ""),
      iif(SuperScriptCount > 0,  "Superscript",       ""),
      iif(DashVariantCount  > 0, "Unicode Dash",      ""),
      iif(HasUnicode,            "Unicode/Non-ASCII", "")
    ),
    pack_array("")
)
| extend ObfCount = array_length(ObfTypes)
| where ObfCount > 0
// --- Final output ---
| project TimeGenerated,
          DeviceName,
          FileName,
          InitiatingProcessFileName,
          ProcessCommandLine,
          ObfTypes,
          Base64Candidate1,
          Decoded,
          NonAsciiCount,
          SuperScriptCount,
          DashVariantCount
| where FileName <> "auditpol.exe"
```
