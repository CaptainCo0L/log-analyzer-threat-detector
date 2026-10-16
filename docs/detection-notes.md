# Detection notes

## Rule: repeated_failed_logins

**Goal:** Identify a source IP with a high number of failed SSH authentication events.

**Current condition:** The IP has at least the configured number of recognized failure events in the input file.

**Potential false positives:** A user with an old saved password, a misconfigured service, or a shared NAT address can generate repeated failures.

## Rule: success_after_repeated_failures

**Goal:** Prioritize a source IP that has a successful SSH authentication after a series of failed attempts.

**Current condition:** In file order, a success follows failures from the same IP and the total number of failures for that IP reaches the configured threshold.

**Limitations:** The first version does not enforce a time window and does not reliably correlate individual usernames or sessions. It should be treated as a learning project, not a production detection system.

## Suggested next improvement

Track events with timestamps and define a configurable time window (for example, 10 minutes). Add tests for events just inside and outside the window before presenting the rule as time-aware.
