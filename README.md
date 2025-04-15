# Hybrid-Firewall

Hybrid Firewall  
A Python-based Hybrid Firewall that combines stateful inspection, packet filtering, and advanced threat detection using machine learning, DPI, GeoIP, and external threat intelligence services.

## Features

- 🔒 **Stateful Inspection**<br>
  Tracks connection states for intelligent packet handling.

- 🚫 **Packet Filtering**<br>
  Supports custom rules to accept, drop, or log packets based on protocol, IP, and port.

- 🔴 **Threat Detection**<br>
  Dictionary attacks  
  Port scans  
  Half-open scans  
  Deep Packet Inspection (DPI) for SQLi, XSS, etc.  
  Anomaly detection via traffic profiling

- 🌍 **GeoIP Filtering**<br>
  Blocks or allows traffic based on country of origin.

- 🧠 **Threat Intelligence Integration**<br>
  Supports AbuseIPDB & Google Safe Browsing for real-time IP/URL reputation checks.

- 🧾 **MITRE ATT&CK Mapping**<br>
  Maps detected attacks to known MITRE techniques for threat context.

## Default Rules

✅ Allow established connections  
❌ Drop SSH brute force attempts  
✅ Allow outbound traffic  
✅ Accept Microsoft telemetry (150.171.0.0/16)

---

Logs: All activity is logged in `firewall.log`.  
GeoIP uses the MaxMind GeoLite2 database (`GeoLite2-Country.mmdb`).
