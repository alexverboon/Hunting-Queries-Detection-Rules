# Defender for Office 365 - Teams Messages

## Query Information

### Description

- The ***MessageEvents*** table in the advanced hunting schema contains details about messages sent and received within your organization at the time of delivery.
- The ***MessageUrlInfo*** table in the advanced hunting schema contains information about URLs sent through Microsoft Teams messages in your organization.
- The ***MessagePostDeliveryEvents*** table in the advanced hunting schema contains information about security events that occurred after the delivery of a Microsoft Teams message in your organization.

Use the below query to retrieve Teams Messages information

#### References

- [Introducing new Advanced Hunting Tables to hunt on Teams messages and URLs](https://admin.microsoft.com/Adminportal/Home?source=applauncher&ref=MessageCenter/:/messages/MC1048617)
- [MessageEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-messageevents-table)
- [MessageUrlInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-messageurlinfo-table)
- [MessagePostDeliveryEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-messagepostdeliveryevents-table)

### Microsoft Defender XDR

Retrieve Teams Messages and links embedded in the teams chat

```kql
MessageEvents 
| join kind=leftouter MessageUrlInfo
on $left. TeamsMessageId == $right. TeamsMessageId
```
