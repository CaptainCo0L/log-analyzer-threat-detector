# Pi-hole DNS Threat Detector

Spots signs of compromise on a home network from the DNS queries Pi-hole already sees, and tells the
owner so a person can judge them.

## Language

### Devices

**Device**:
A physical thing on the network, such as the iPad or the fridge. It may use several MACs over time.
_Avoid_: Client, host, MAC

**Client**:
One entry in Pi-hole's Clients list, giving a MAC or IP a comment and groups. A device may have several.
_Avoid_: Using this word for the device that sends queries

**Label**:
What a device is called wherever a person reads about it.
_Avoid_: Friendly name, display name, client

**Private MAC**:
A MAC a device made up for itself, which it may replace on its own.
_Avoid_: Random MAC

**Burned-in MAC**:
A device's permanent, factory-assigned MAC.
_Avoid_: Real MAC, hardware MAC

**Rotation**:
A device moving to a new private MAC.

**Rotation sync**:
Giving a device's new private MAC the Clients entry of its old one, so it keeps its comment and groups.

### DNS traffic

**Query**:
One DNS question a device asked Pi-hole.
_Avoid_: Lookup, request

**Resolved**:
Said of a query that Pi-hole answered with a real result: neither blocked nor NXDOMAIN.
_Avoid_: Allowed, succeeded

**Blocked**:
Said of a query Pi-hole refused to answer truthfully because of its own lists or rules.

**Apex**:
The part of a domain name someone can register: `example.co.uk` for `www.example.co.uk`. Hosting
platforms' suffixes don't count as public suffixes, so `cloudfront.net` is itself an apex.
_Avoid_: Registrable domain, root domain, parent domain

**Noisy apex**:
An apex that legitimately fans out across thousands of subdomains, so tunneling doesn't count it.

**Threat-intel list**:
The list of domains known to be malicious. A match means something whether or not Pi-hole blocked it.
_Avoid_: Blocklist, TIF

### Baseline

**Relationship**:
The pairing of one device and one apex it has queried.

**Learning period**:
The first seven days after a device is first seen, while its normal behaviour is being recorded.
_Avoid_: Learning week, shadow week

**Familiarity**:
How established a relationship is: **Learning** (the device is still in its learning period), **Known**
(the apex was seen in that period, or the relationship has outlasted one) or **New** (anything else).

**Shared apex**:
An apex that many devices have queried, which makes it platform infrastructure, not one device's anomaly.

### Alerts

**Rule**:
One named way of recognising suspicious behaviour.
_Avoid_: Detection, check, heuristic

**Alert**:
A triage signal that a rule raised for a person to judge. Never proof of compromise.
_Avoid_: Detection, finding, incident

**Push**:
Sending one alert to the owner's phone as it happens. Only HIGH alerts are ever pushed.
_Avoid_: Instant alert, notification

**Shadow mode**:
Running with pushes off, so thresholds can be tuned before anything reaches the phone.

**Mute**:
Stopping pushes for one rule on one device for a while. Those pushes are never sent, though the alerts
are still logged and appear in the digest.
_Avoid_: Silence, snooze

**Hold**:
Delaying all pushes until a set time, or through quiet hours, then delivering them as one summary.
_Avoid_: Mute, pause

**Digest**:
The daily message summarising alerts, sent even when empty so that its absence means the detector is down.
_Avoid_: Daily report

**Report**:
A summary of past alerts produced on request, for a chosen number of days.
_Avoid_: Digest
