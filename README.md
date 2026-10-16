# Log Analyzer & Threat Detector

A small Blue Team / SOC portfolio project that analyzes Linux SSH authentication logs and flags suspicious authentication patterns.

## Features

- Parses common Ubuntu/Debian-style `/var/log/auth.log` SSH messages.
- Counts failed SSH logins by source IP.
- Alerts when an IP reaches a configurable failed-login threshold.
- Detects a successful SSH login after repeated failures from the same IP in the analyzed log.
- Prints a readable summary and optionally exports alerts to JSON.
- Includes synthetic sample logs and automated tests.

> **Safety and scope:** This tool analyzes log files offline. It does not scan networks, attempt logins, or monitor systems in real time. The sample data is synthetic and uses documentation-only IP addresses.

## Requirements

- Python 3.10+
- No third-party dependencies for the analyzer
- `pytest` to run the test suite

## Quick start

```bash
python src/log_analyzer.py samples/auth.log
```

Set the failed-login threshold:

```bash
python src/log_analyzer.py samples/auth.log --threshold 5
```

Export alerts to JSON:

```bash
python src/log_analyzer.py samples/auth.log --json-out reports/alerts.json
```

The output directory is created automatically.

## Run tests

```bash
python -m pip install pytest
python -m pytest -v
```

## Example output

```text
Log Analyzer & Threat Detector
File: samples/auth.log
Parsed SSH events: 10
Failed logins: 7
Successful logins: 2
Unique source IPs: 3

ALERTS
[HIGH] Repeated failed SSH logins from 192.0.2.10 (5 failures)
[MEDIUM] Successful SSH login from 192.0.2.10 after 5 recorded failure(s)
```

Exact counts depend on the sample log and configured threshold.

## Detection logic

1. **Repeated failures:** alert when an IP has at least `--threshold` failed SSH login events in the input file.
2. **Success after failures:** alert if a source IP has a successful login after its failures in the analyzed event sequence, and its total failures reach the threshold.

These are triage signals, not proof of compromise. Legitimate users can mistype passwords, and an attacker may use distributed IPs or avoid triggering the threshold.

## Supported log patterns

The initial version recognizes common SSH messages such as:

- `Failed password for ... from <IP>`
- `Invalid user ... from <IP>`
- `Accepted password for ... from <IP>`
- `Accepted publickey for ... from <IP>`

Log formats vary by Linux distribution and SSH configuration. Unrecognized lines are skipped.

## Project structure

```text
log-analyzer-threat-detector/
├── README.md
├── src/
│   └── log_analyzer.py
├── tests/
│   └── test_log_analyzer.py
├── samples/
│   └── auth.log
├── docs/
│   └── detection-notes.md
├── requirements-dev.txt
└── .gitignore
```

See [`IMPROVEMENTS.md`](IMPROVEMENTS.md) for the detailed improvement plan covering time-window detection, edge-case tests, and GitHub Actions CI.

## Roadmap

- [ ] Add support for journald exports
- [ ] Add configurable time windows
- [ ] Add CSV export
- [ ] Add optional IP enrichment using a trusted offline dataset
- [ ] Add CI workflow to run tests on every push

## Ethical use

Only analyze logs you are authorized to access. Remove usernames, public IPs, hostnames, and other sensitive information before publishing logs.
