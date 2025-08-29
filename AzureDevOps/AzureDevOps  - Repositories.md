# DevOps - Azure DevOps Inventory

## Query Information

### Description

Use the below query to identify Azure DevOps projects and repositories.

#### References

### Microsoft 365 Defender

```kql
ExposureGraphNodes 
| where NodeLabel == @"azuredevopsrepository"
| extend Subscription = parse_json(EntityIds)[0]["id"]
| extend URL = parse_json(EntityIds)[1]["id"]
| parse Subscription with 
    "/subscriptions/" subscription_id 
    "/resourcegroups/" resource_group 
    "/providers/microsoft.security/securityconnectors/" * 
    "/devops/default/azuredevopsorgs/" azure_devops_org 
       "/projects/" project_name "/repos/" repo_name
| project NodeName, Subscription, URL,subscription_id, resource_group, azure_devops_org, project_name, repo_name
```
