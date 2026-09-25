# SOC Home Lab

This project is a small SOC home lab I built using Splunk, Windows and Sysmon.

The goal was to learn how a SIEM collects logs, detects suspicious activity and helps investigate security events.

## Lab Setup

- Windows 11 – monitored endpoint
- Sysmon – process monitoring
- Splunk Universal Forwarder – sends logs
- Kali Linux – hosts Splunk Enterprise
- Splunk Enterprise – log analysis and alerts

### Architecture

Windows 11  
↓  
Windows Event Logs + Sysmon  
↓  
Splunk Universal Forwarder  
↓  
Splunk Enterprise (Kali Linux)

## What I Monitored

I collected Windows Security logs and Sysmon events in Splunk.

Some of the main events I looked at were:

- 4624 – Successful login
- 4625 – Failed login
- Sysmon Event ID 1 – Process creation

<img width="1274" height="452" alt="image" src="https://github.com/user-attachments/assets/0744b17a-b373-4eb6-a021-a44fa07e9a46" />


## Failed Login Detection

I created an SPL search to detect 3 or more failed logins within 5 minutes.

```spl
index=main source="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count by Account_Name, _time
| where count >= 3
```

I then turned this into a scheduled Splunk alert.

![Failed Login Alert](screenshots/failed-login-alert.png)

## PowerShell Detection

I used Sysmon to detect PowerShell processes using `ExecutionPolicy Bypass`.

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
"powershell.exe"
"ExecutionPolicy Bypass"
```

![PowerShell Detection](screenshots/powershell-detection.png)

## Dashboard

I created a dashboard to monitor:

- Failed logins over time
- Failed logins by account
- Suspicious PowerShell activity
- Windows security events

![SOC Dashboard](screenshots/soc-dashboard.png)

## Investigation

I also simulated suspicious PowerShell activity and investigated it using Sysmon.

I was able to identify the PowerShell command and see that it launched `notepad.exe` as a child process.

```text
powershell.exe
    └── notepad.exe
```

![Investigation](screenshots/incident-investigation.png)

## What I Learned

This project gave me practical experience with:

- Splunk and SPL
- Windows Event Logs
- Sysmon
- Creating detection rules
- Configuring alerts
- Building dashboards
- Investigating process activity

## Files

- `detections/` – SPL detection queries
- `config/` – Splunk configuration
- `screenshots/` – Lab evidence
