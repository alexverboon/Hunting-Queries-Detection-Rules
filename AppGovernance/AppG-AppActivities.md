// Find all the activities involving the cloud app in last 30 days
let now = now();
let appid = (i : dynamic )
{
    case
    (
        i.Workload == "SharePoint", i.ApplicationId,
        i.Workload == "Exchange", iff(isempty(i.ClientAppId), i.AppId, i.ClientAppId),
        i.Workload == "OneDrive", i.ApplicationId,
        i.Workload == "MicrosoftTeams", i.AppAccessContext.ClientAppId,
        "Unknown"
    )
};
CloudAppEvents
| where ((RawEventData.Workload ==  "SharePoint" or RawEventData.Workload == "OneDrive") and (ActionType == "FileUploaded" or ActionType == "FileDownloaded")) or (RawEventData.Workload == "Exchange" and (ActionType == "Send" or ActionType == "MailItemsAccessed")) or (RawEventData.Workload == "MicrosoftTeams" and (ActionType == "MessagesListed" or ActionType == "MessageRead" or ActionType == "MessagesExported" or ActionType == "MessageSent"))
| extend AppId = appid(RawEventData)
| where AppId == ""
| where Timestamp between (datetime("2023-05-07 00:00:00Z")..30d)
| extend tostring(RawEventData.Id)
| summarize arg_max(Timestamp, *) by RawEventData_Id
| sort by Timestamp desc
| project Timestamp, OAuthApplicationId = AppId, ReportId, AccountId, AccountObjectId, AccountDisplayName, IPAddress, UserAgent, Workload = tostring(RawEventData.Workload), ActionType, SensitivityLabel = tostring(RawEventData.SensitivityLabelId), tostring(RawEventData)
| limit 1000