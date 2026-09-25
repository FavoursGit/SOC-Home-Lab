# SOC Home Lab – Splunk & Sysmon

A SOC home lab built to practice log analysis, detection engineering, alerting, and incident investigation using Splunk.

## Lab Overview

The lab collects Windows security logs and Sysmon telemetry from a Windows endpoint and forwards them to Splunk Enterprise running on Kali Linux.

### Architecture

Windows Endpoint  
↓  
Windows Event Logs + Sysmon  
↓  
Splunk Universal Forwarder  
↓  
Splunk Enterprise  
↓  
Detections, Alerts & Dashboard

## Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Logs
- Kali Linux
- VirtualBox
- SPL

## Detections

### Multiple Failed Logins

Detects accounts with 3 or more failed login attempts within 5 minutes.

```spl
index=main source="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count by Account_Name, _time
| where count >= 3
