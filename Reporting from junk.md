### Users reporting phishing emails from their junk folder

<p>In what was undoubtedly meant to be helpful user behavior, we found a non-zero number of users reporting
phishing emails from their junk folder. The corrective actions arising from this was beyond
the scope of our study, but finding them was an interesting task in and of itself. See below for the query logic that uncovered these mis-reported messages.</p>

<p>Upon reviewing this KQL, you may be asking yourself--why is it being done this way?<br>
Reporting as phishing kicked off a transport rule that sent a copy of the message to our phishing mailbox, appending the subject line
with an identifier and message, which we stripped out as an identifying filter condition ('phishing' or 'reportphishing' message prepend) and then joined back on the EmailEvents table to figure out which reported emails were initially delivered as junk from the outset.
</p>

```kusto
EmailEvents
| where Timestamp > ago(30d)
| where RecipientEmailAddress == "spamreport@acme.corp"
| where DeliveryAction == "Delivered"
| extend ReportType = extract (@"(\w+)\:([\w\-]+)",1,Subject)
| where ReportType has_any ("phishing","reportphishing")
| extend OriginalNetworkMessageId = toguid(extract(@"(\w+)\:([\w\-]+)",2,Subject))
| project ReportType, OriginalNetworkMessageId
  ,ReportingUser = SenderDisplayName
  ,Sender = SenderFromAddress
| join EmailEvents on $left.OriginalNetworkMessageId == $right.NetworkMessageId
| where Delivery Location has "junk"
| summarize ReportedEmails = count_distinct(OriginalNetworkMessageId) by ReportingUser


```
