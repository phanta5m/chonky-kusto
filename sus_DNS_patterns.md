## Sus DNS patterns
#### Excessively long DNS queries which can be indicative of C2 traffic

<p>Looks at DNS traffic, attempts to filter by long subdomain lengths, Base64 patterns, Hex Patterns, Random characters, etc</p>

- The first one lists risk profile determinations as assessed by Microsoft
- The second one lists 30 days of changes to the user's account

```kusto
//DNS queries with suspicious characteristics
let MinFQDNLength = 180;
let MinSubdomainLength = 60;
let Base64Pattern = @"([A-Za-z0-9+/]{20,}={0,2})";
let HexPattern = @"\b[a-fA-F0-9]{20,}\b";
let MixedPattern = @"\b[a-zA-Z0-9]{25,}\b";
let EntropyLikePattern = @"\b[b-df-hj-np-tv-z0-9]{25,}\b";
cisco_umbrella_dns
| where timestamp > ago(14d)
| extend fqdnLength = strlen(domain)
| extend Subdomains = split(domain, ".")
| mv-apply Subdomain = Subdomains on (
    summarize HasLongSubdomain = any(strlen(Subdomain) >= MinSubdomainLength)
)
| extend IsSuspiciousQueryType = querytype has_any ("TXT", "NULL", "ANY")
| extend IsBase64 = isnotempty(extract(Base64Pattern, 0, domain))
| extend IsHex = isnotempty(extract(HexPattern, 0, domain))
| extend IsHighEntropy = isnotempty(extract(MixedPattern, 0, domain)) or isnotempty(extract(EntropyLikePattern, 0, domain))
| where fqdnLength >= MinFQDNLength 
    and (HasLongSubdomain 
    or IsSuspiciousQueryType 
    or IsBase64 
    or IsHex
    or IsHighEntropy)
| where identities !in ("GuestWifi_Out_ATT","QTS Infoblox","DFT Infoblox")
| where not (domain has_any("measure.office.com","googlesyndication.com","conviva.com"))
| project timestamp, identities, domain, fqdnLength, querytype, action,
          HasLongSubdomain, IsSuspiciousQueryType, IsBase64, IsHex, IsHighEntropy
| order by timestamp desc
```
