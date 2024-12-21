### KQL to find malicious html phishing attachments
- The objective here is to find the prevalance of these types of attachments using regex matches.
- The regex can be used as part of a security focused Exchange Transport Rule.
- The last line of the kusto query can also be uncommented out, post-transport rule implementation, to see if it's been successful in filtering out these types of attachments.
