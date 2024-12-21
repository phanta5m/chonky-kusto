## This query uses regex to match 3 naming schema, all related to voicemails.

<ul>
<li>Voicemails continue to be a common and successful phishing vector</li>
<li>This query can identify the prevalence of voicemail themed html attachments</li>
<li>The same query logic can be used to build Exchange Transport rules (specifically, the regex)</li>
</ul>

```kusto
EmailAttachmentInfo
| where Timestamp > ago (30d)
| where FileType contains "html"
| where FileName matches regex @"[^a-zA-Z0-9]VM[^a-zA-Z0-9]" // any variation of 'VM'
or FileName matches regex @"^Aud.|.[A|a]ud" // any variation of 'Aud'
or FileName matches regex @".[P|p]lay|[P|p]lay." // any variation of 'Play"
or FileName matches regex @"[\d\W_][C][A-Z]{3}\.html$" // any 4 letter string starting with 'C" like 'CLRQ' which was a naming schema we identified in multiple campaigns
| join EmailEvents on NetworkMessageId | where DeliveryAction != "Blocked"
| where SenderFromDomain !in~ ("exclusion1.org","exclusion2.edu","exclusion3.com") // if you need to exclude known intra-org senders that might get caught
| project-reorder Timestamp, Filename, Subject, SenderDisplayName, SenderFromAddress,SenderFromDomain
//| where OrgLevelPolicy has "Exchange" //uncomment this line out later to see wh ich ones were caught by the new exchange transport rule
```
