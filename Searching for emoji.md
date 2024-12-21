### Searching for emoji in subject lines

- Phishing kit often feature phone, musical note, or other audio related emoji in subject lines.
- Although many non-malicious emails (i.e. marketing spam) also use emoji, this was another use of regex in identifying potentially sus messages.

```kusto
let days = 7d;
EmailEvents
| where Timestamp > ago (days)
| where DeliveryAction has "Delivered"
//| where ConfidenceLevel has_any ("spam","phish")
| extend Chars = extract_all(@"([\u{FF0D}-\u{1FAF9}0+)",Subject)
| where not (isnull(Chars))
| summarize Timestamp = max(Timestamp), Subject = make_set(Subject)
,Chars = make_set(Chars)
,NetworkMessageId = make_set(NetworkMessageId) by SenderFromAddress
```

### This regex syntax can also be implemented in other tables, like DeviceProcessEvents

```kusto
let days = 7d;
DeviceProcessEvents
| where Timestamp > ago (days)
| where ProecssCommandLine matches regex @"([\u{FF0D}-\u{1FAF9}]+)"
```
