# Microsoft Sentinel - TAXII Connector failures

## Query Information

### Description

When configuring the TAXII Connector in Sentinel, you might get the follwing error message:

Failed to add TAXII connector
The TAXII connector could not be configured due to an unexpected error.

Use the below query to retrieve Microsoft Sentinel TAXII Connector errors from the Azure Activity log. 

Tip: Make sure that you have the latest version of the TAXII connector installed, check the Sentinel Content Hub for updates. 

### Log Analytics (requires Azure Activity logs)

```kql
AzureActivity
| where Level == "Error"
| where OperationNameValue == "MICROSOFT.SECURITYINSIGHTS/DATACONNECTORS/WRITE"
| extend resourceGroup_ = tostring(parse_json(Properties).resourceGroup)
| extend code = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).statusMessage)).error)).code)
| extend message = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).statusMessage)).error)).message)
| where message contains "TAXII"
| project TimeGenerated, ResourceGroup, Caller, code, message
```
