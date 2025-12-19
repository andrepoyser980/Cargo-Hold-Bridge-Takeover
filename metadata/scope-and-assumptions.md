# Scope and Assumptions

## Scope
- Endpoints monitored via Microsoft Defender for Endpoint
- Systems with hostnames containing `azuki`
- Activity between **2025-11-19** and **2025-11-30**
- Focus on credential access, lateral movement, staging, and exfiltration

## Assumptions
- Logs provided by Defender for Endpoint are accurate and complete
- No additional EDR or network telemetry was available
- Cloud or identity provider logs were out of scope
- Attribution is based on behavior, not threat actor identity
