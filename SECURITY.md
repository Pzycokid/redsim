# Security Policy

## Authorized Use Only

RedSim is designed exclusively for **authorized security research, academic study, and isolated lab environments**.

This framework:
- Contains **no real malware** or exploit payloads
- Uses safe simulation primitives that generate log telemetry without executing OS commands
- Is intended to test detection rules, SIEM pipelines, and SOC playbooks — not for offensive use

## Prohibited Uses

- Running against systems you do not own or have explicit written permission to test
- Extracting or repurposing any module for use in real-world attacks
- Any activity that violates applicable laws or regulations

## Reporting a Vulnerability

If you discover a security vulnerability in RedSim itself, please open a GitHub Issue with the label `security` rather than disclosing it publicly.

## Responsible Disclosure

This project follows responsible disclosure practices. Reports that suggest misuse of this framework as a real attack tool will not be addressed.
