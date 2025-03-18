## Hunt for phishing attachments arriving as .SVG's (bc your .HTML transport rules based on similar logic basically eliminated them as a vector)
#### API call of 3 word lists (see list above)

<p>Importing a trigger word list, list of safe senders, and subject phrases to exclude</p>

- The first import is a list of words I've found to be correlated with phishing emails
- The second one is a list of phrases that, when found in the subject field, should be excluded
- The third one is a list of sender domains we want to exclude

```kusto
let t = 24h;
let sus_words = externaldata (Word: string) [
    h'https://raw.githubusercontent.com/phanta5m/chonky-kusto/refs/heads/main/html_svg_triggers/sus_words.md'
] with (format="txt");
let safe_subjects = externaldata (Word: string) [
    h'https://raw.githubusercontent.com/phanta5m/chonky-kusto/refs/heads/main/html_svg_triggers/safe_subjects.md'
] with (format="txt");
let safe_sender_domains = externaldata (Word: string) [
    h'https://raw.githubusercontent.com/phanta5m/chonky-kusto/refs/heads/main/html_svg_triggers/safe_sender_domains.md'
] with (format="txt");
/////////////////////////////BRUHHHHHHHHHHHHHHHHHHHHHHHHHH//////////////////////////////////////////
EmailEvents
| where Timestamp > ago (t) | where DeliveryAction !in~ ("junked","blocked") 
| where not(Subject has_any (safe_subjects)) and Subject has_any (sus_words) | where SenderFromDomain !in~ (safe_sender_domains)
| join EmailAttachmentInfo on NetworkMessageId
| where FileName endswith "svg" or FileName endswith "xhtml" and FileName !contains "logo"
//| where FileName has_any (sus_words)
| where LatestDeliveryLocation has "inbox"
| project Timestamp,Subject, SenderDisplayName,SenderFromAddress,FileName,FileType,DeliveryAction,NetworkMessageId, LatestDeliveryLocation
//| project NetworkMessageIdWithComma = strcat(tostring(NetworkMessageId), ",")
```
