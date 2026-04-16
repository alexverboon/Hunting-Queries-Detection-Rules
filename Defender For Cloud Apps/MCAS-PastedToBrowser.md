# Defender for Cloud Apps - PastedToBrowser

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: In Progress](https://img.shields.io/badge/status-in--progress-yellow.svg)

## Query Information

### Description

PastedToBrowser events

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
CloudAppEvents
| where ActionType == @"PastedToBrowser"
| extend TargetUrl = tostring(parse_json(RawEventData)["TargetUrl"])
| where TargetUrl == @"https://chatgpt.com/"
```


