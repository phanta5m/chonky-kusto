## Some queries for investigating impossible travel or anomalous tokens

### Description

That Entra can be interminably slow probably does not come as a surprise. These queries can be helpful in pulling sign-in data more quickly.
These queries aren't a replacement for in-depth investigations, but they can be helpful in quickly seeing details and assisting in the closure of the innocuous tickets.

### Source Parameters
| Type     | Description |
|-----------------|----------------------------------|
| Interactive sign-ins   | This query looks at the interactive sign-in logs over 30 days, lists the device ID if available, and renders a pie chart, showing the locations from which the user has signed in. |
| Non-interactive sign-ins   | This query looks at the non-interactive sign-in logs, which can often show the Azure joined devices and their respective device ID. Because of the volume of log entries, 14 days can serve as a good starting point, expanding from there if necessary |
| Audit logs   | This one combined a Risk Events table along with the Audit Log. The first table is a good way to confirm that alert logic worked and triggered a password reset, and the second one gives an overview of everything that happened over the last month |
| Sus logins from "X" IP | A simple query looking at all sign-ins from an IP address flagged as potentially malicious |
