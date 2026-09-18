![CI Pipeline](https://github.com/Haidriyam/network-threat-recon/actions/workflows/ci.yml/badge.svg)

# Network Infrastructure & TLS Posture Recon Engine

A lightweight, concurrent network diagnostic tool designed to evaluate public-facing DNS topology, certificate chain validity, and misconfiguration indicators.

```text
[ Domain Target ] ──► [ Async DNS Resolver ] ──► (MX / SPF / TXT / A)
                 └──► [ TLS Handshake Probe ] ──► (Chain / SANs / Expiry)
