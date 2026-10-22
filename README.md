# NetworkIDS

A defensive network intrusion detection toolkit for analyzing authorized network captures and Suricata EVE JSON logs.

## Status

Initial project setup. Detection results are generated from supplied evidence; the tool does not fabricate alerts or automatically block traffic.

## Planned capabilities

- Offline PCAP/PCAPNG analysis with Scapy
- Suricata EVE JSON ingestion
- Stateful detection for TCP SYN port scans and connection fan-out
- Evidence-backed findings with rule IDs, severity, timestamps, and investigation guidance
- JSON and CSV reports
- Automated tests and CI

## Safety and scope

Use only captures and logs you are authorized to analyze. This project is for defensive monitoring and offline analysis. It does not perform automatic blocking or packet injection.

## Development

Python 3.11 or newer is recommended. The first implementation will focus on reproducible offline analysis and tests before any optional live-capture functionality is considered.
