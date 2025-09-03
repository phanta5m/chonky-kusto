## Check for phishing domains appearing in Cisco Umbrella DNS Logs
#### Scrape a repo with regularly updated domain lists, compare against internal logs

<p>Requires some data normalization (yay, regex)</p>

- Many thanks to /Phishing-Database
- This is resource intensive, and has difficulty running beyond 1-2 hour timeframes.

```kusto
let x = 2h;
let phishing_domains = externaldata (Domain: string) [
    h'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-NEW-today.txt'
] with (format="txt");
let phishing_domains_cleaned = phishing_domains
| where isnotempty(Domain)
| extend normalized_domain = tolower(trim(" ", Domain));
let dns_cleaned = cisco_umbrella_dns
| where timestamp > ago(x)
| where policy_identity !in~ ("GuestWifi_Out_ATT","DFT Infoblox")
| extend queried_domain = tolower(trim_end(".", domain))
| where isnotempty(queried_domain);
dns_cleaned
| join kind=inner (
    phishing_domains_cleaned
    | project normalized_domain
) on $left.queried_domain == $right.normalized_domain
```
