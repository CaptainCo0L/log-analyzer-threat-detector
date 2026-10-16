# Planned Improvements

This document tracks the next improvements for the **Log Analyzer & Threat Detector** portfolio project. These are implementation goals, not claims that the features are already complete.

## 1. Add time-window-based detection

### Current limitation
The initial implementation counts failed logins across the entire input file and correlates events in file order. Old failures can therefore contribute to an alert even when they occurred hours or days before the later event.

### Proposed behavior
- Add a `--window-minutes` command-line option, with a documented default such as `10` minutes.
- Parse each event's timestamp and associate events with a time window.
- Trigger a repeated-failure alert only when one source IP reaches the configured threshold inside the selected window.
- Trigger a success-after-failures alert only when a successful login occurs after the threshold number of failures from the same IP within that window.
- Keep event ordering and time-window behavior deterministic and document how the tool handles timestamps that omit a year and timezone, as is common in syslog files.
- Report the relevant time range and number of matching events in each alert's evidence.

### Acceptance criteria
- Five failures from one IP within ten minutes trigger the default threshold alert.
- Five failures spread across a time span longer than the selected window do not trigger a window-based alert.
- A success after enough recent failures triggers the success-after-failures alert.
- A success that happened before the failures does not trigger the success-after-failures alert.
- Events from different IP addresses are evaluated independently.

## 2. Expand edge-case and regression tests

Use `pytest` to cover detection boundaries and unusual input. At minimum, add tests for:

- One fewer than the threshold, exactly the threshold, and one more than the threshold.
- Failures just inside and just outside the configured time window.
- A success before failures and a success after failures.
- Interleaved events from multiple source IPs.
- Unrecognized lines, blank lines, malformed timestamps, and empty files.
- Repeated events with the same timestamp.
- Timestamps crossing midnight, with the chosen year/timezone assumptions documented.
- IPv4 addresses and any supported IPv6 format.
- Invalid threshold and window values, including zero and negative numbers.
- JSON output creation and errors writing the report.

### Acceptance criteria
- Tests are deterministic and use synthetic data rather than real authentication logs.
- Every detection rule has both a positive and negative test.
- Existing behavior remains covered so future changes do not silently break previously supported log patterns.
- The full test suite passes locally with `python -m pytest -v`.

## 3. Add GitHub Actions continuous integration

Create `.github/workflows/tests.yml` to run the test suite on every push and pull request.

Recommended workflow behavior:
1. Check out the repository.
2. Set up supported Python versions (for example, Python 3.10, 3.11, and 3.12).
3. Install the development requirements from `requirements-dev.txt`.
4. Run `python -m pytest -v`.
5. Fail the workflow if tests fail.

Keep the workflow read-only and limited to testing. It should not require secrets, access real systems, or upload authentication logs.

### Acceptance criteria
- A push or pull request starts the workflow automatically.
- Each configured Python version runs the tests successfully.
- The README explains how to view the workflow status and run the same tests locally.

## Suggested implementation order

1. Define and document timestamp parsing and time-window semantics.
2. Implement the time-window detection rules.
3. Add focused tests for threshold boundaries, ordering, and time windows.
4. Run the complete test suite and fix regressions.
5. Add the GitHub Actions workflow.
6. Update the README with the final behavior, CLI examples, known limitations, and CI status.

## Security and data handling

- Use synthetic or properly sanitized samples in the public repository.
- Do not commit real usernames, hostnames, public IP addresses, tokens, or other sensitive log content.
- Describe alerts as indicators for human triage, not proof that a system was compromised.
- Document false-positive cases, including users mistyping passwords, shared NAT addresses, and misconfigured services.
