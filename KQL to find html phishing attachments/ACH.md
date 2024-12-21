### ACH html phishing attachments

#### Simpler than the voicemail query using regex; this uses a 'has' function to string match

```kusto
EmailAttachmentInfo
| where Timestamp > ago (30d)
| where FileType contains "html"
| where FileName has_any ("acheft","eftach","ach")
| join EmailEvents on NetworkMessageId
| where SenderFromDomain !in~ ("exclusion1.org","exclusion2.edu","exclusion3.com")
| where DeliveryAction == "Delivered"
| project-reorder Timestamp, Filename, Subject, SenderDisplayName, SenderFromAddress,FileName, FileType
| sort by Timestamp desc
```
