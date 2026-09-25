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

<img width="1361" height="593" alt="image" src="https://github.com/user-attachments/assets/c43c1c8e-d640-4053-9754-284a517b5768" />



## Failed Login Detection

I created an SPL search to detect 3 or more failed logins within 5 minutes.

```spl
index=main source="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count by Account_Name, _time
| where count >= 3
```

I then turned this into a scheduled Splunk alert.

<img width="1363" height="467" alt="image" src="https://github.com/user-attachments/assets/28cca5da-f106-447a-9a0f-852805164eae" />



## PowerShell Detection

I used Sysmon to detect PowerShell processes using `ExecutionPolicy Bypass`.

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
"powershell.exe"
"ExecutionPolicy Bypass"
```

<img width="883" height="444" alt="image" src="https://github.com/user-attachments/assets/24b116bf-ea9f-4282-90ac-a22e4694ee90" />


## Dashboard

I created a dashboard to monitor:

- Failed logins over time
- Failed logins by account
- Suspicious PowerShell activity
- Windows security events

<img width="1369" height="242" alt="image" src="https://github.com/user-attachments/assets/5f31c869-1718-4cbd-9285-aafce6ce0404" />
<img width="1084" height="350" alt="image" src="https://github.com/user-attachments/assets/fa7d6834-d4a9-4225-ae17-ef4ccd92bb4a" />
<img width="1109" height="348" alt="image" src="https://github.com/user-attachments/assets/75cd2ae9-1364-4438-8aa6-0e65f23eaa2c" />
<img width="1096" height="466" alt="image" src="https://github.com/user-attachments/assets/b3c3b199-095d-421c-be08-adfa602f450e" />
<img width="1101" height="293" alt="image" src="https://github.com/user-attachments/assets/3bb0bf61-5acf-427d-a1ed-0732fa2f2a05" />



## Investigation

I also simulated suspicious PowerShell activity and investigated it using Sysmon.

I was able to identify the PowerShell command and see that it launched `notepad.exe` as a child process.

```text
powershell.exe
    └── notepad.exe
```

<img width="1365" height="552" alt="image" src="https://github.com/user-attachments/assets/2628831c-12df-42f5-8518-df6508ed8dcd" />


## What I Learned

This project gave me practical experience with:

- Splunk and SPL
- Windows Event Logs
- Sysmon
- Creating detection rules
- Configuring alerts
- Building dashboards
- Investigating process activity
