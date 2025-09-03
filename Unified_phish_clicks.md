## Unified Phish Clicks
#### EmailUrlInfo + UrlClickEvents combined

<p>Creates a master list of all emails that contain a URL string + returns a list of people who clicked</p>

- The DeliveryLocation has "inbox" lines can be uncommented, to focus on just the ones currently in inboxes
- The Url_list is the defacto projection method; uncommenting the rest of the line starting with '| summarize NetworkMessageIds' gets you a list of NMID's that can be pasted into Defender Explorer for quick remediation
- Commenting out Url_list and uncommenting the last line starting with 'Clicks' will give you a list of all the people who clicked, along with their UPN's

```kusto
let t = (30d);
let partial_string = dynamic([
"supersus_url"
]);
let Url_list = EmailUrlInfo
| where Url has_any (partial_string)
| join EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered" //| where DeliveryLocation has "inbox"
| where RecipientEmailAddress !in~ ("spam@service-now.com","spamreport@test.org") | where SenderFromAddress != "spam@service-now.com" | where Subject !has "FW: Incident"
| summarize arg_min(Timestamp,*) by NetworkMessageId,Subject, SenderDisplayName, SenderFromAddress, RecipientEmailAddress, Url, LatestDeliveryLocation;
let Clicks = UrlClickEvents
| where Url has_any (partial_string)
| join EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"// | where DeliveryLocation has "inbox"
| where RecipientEmailAddress !in~ ("spam@service-now.com","spamreport@test.org") | where SenderFromAddress != "spam@service-now.com" | where Subject !has "FW: Incident"
| summarize arg_min(Timestamp,*) by NetworkMessageId,ActionType,Subject, SenderDisplayName, SenderFromAddress, RecipientEmailAddress, Url, LatestDeliveryLocation;
Url_list //| summarize NetworkMessageIds = strcat_array(make_list(NetworkMessageId), ", "), count = count()
//Clicks | join IdentityInfo on $left.RecipientEmailAddress == $right.EmailAddress | where not(AccountUpn has_any ("@rush.","@advocate."))| distinct AccountUpn
```
