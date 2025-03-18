'''kusto
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
'''
