# Log Analyzer - Domain Knowledge Reference

## Overview

This document covers the essential knowledge you need to build a log analyzer for authentication events. Study this before writing code - understanding the domain will make your implementation decisions much clearer.

---

## Part 1: Windows Security Event Logs

### Key Event IDs for Authentication

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| **4624** | Successful logon | Core event - someone authenticated successfully |
| **4625** | Failed logon | Critical for detecting brute force, credential stuffing |
| **4634** | Logoff | Helps calculate session duration |
| **4647** | User-initiated logoff | Distinguishes intentional vs forced logoffs |
| **4648** | Explicit credential logon | Someone used different creds (runas, etc.) |
| **4672** | Special privileges assigned | Admin/elevated logon - high interest |
| **4776** | NTLM authentication attempt | Domain controller credential validation |

### Logon Types (Found in Event 4624/4625)

| Type | Name | Description | Security Relevance |
|------|------|-------------|-------------------|
| 2 | Interactive | Physical keyboard logon | Normal user activity |
| 3 | Network | Access from network (file share, etc.) | Lateral movement indicator |
| 4 | Batch | Scheduled task execution | Could be persistence mechanism |
| 5 | Service | Service started | Service account activity |
| 7 | Unlock | Workstation unlocked | Normal activity |
| 8 | NetworkCleartext | Network logon with cleartext creds | Security concern! |
| 9 | NewCredentials | RunAs with /netonly | Credential usage |
| 10 | RemoteInteractive | RDP logon | Remote access - watch closely |
| 11 | CachedInteractive | Cached credentials used | Offline logon |

### Windows Event Log XML Structure

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2024-01-15T14:32:18.123456Z" />
    <Computer>WORKSTATION01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">CORPORATE</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.1.105</Data>
    <Data Name="IpPort">49823</Data>
    <Data Name="WorkstationName">REMOTE-PC</Data>
    <Data Name="LogonProcessName">User32</Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
  </EventData>
</Event>
```

### Research Questions (Answer These!)

1. What's the difference between TargetUserName and SubjectUserName in event 4624?
2. Why would LogonType 3 from an unusual IP be concerning?
3. What pattern of 4625 events indicates a brute force attack?
4. Why is Event 4648 interesting from a threat hunting perspective?

---

## Part 2: Linux Authentication Logs

### Log Locations

| Distribution | Primary Auth Log | Alternative |
|--------------|------------------|-------------|
| Ubuntu/Debian | `/var/log/auth.log` | `/var/log/syslog` |
| RHEL/CentOS | `/var/log/secure` | `/var/log/messages` |
| Arch Linux | `/var/log/auth.log` | journalctl |

### Log Format (Syslog Standard)

```
MMM DD HH:MM:SS hostname service[pid]: message
```

Example:
```
Jan 15 14:32:18 webserver sshd[12345]: Accepted publickey for admin from 192.168.1.50 port 52413 ssh2
```

### Key Patterns to Parse

**Successful SSH Login:**
```
sshd[PID]: Accepted (password|publickey) for USERNAME from IP port PORT ssh2
```

**Failed SSH Login:**
```
sshd[PID]: Failed password for USERNAME from IP port PORT ssh2
sshd[PID]: Failed password for invalid user USERNAME from IP port PORT ssh2
```

**Session Events:**
```
sshd[PID]: pam_unix(sshd:session): session opened for user USERNAME
sshd[PID]: pam_unix(sshd:session): session closed for user USERNAME
```

**Sudo Usage:**
```
sudo: USERNAME : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/command
sudo: USERNAME : command not allowed ; TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/badcmd
```

**User Switching:**
```
su[PID]: Successful su for root by USERNAME
su[PID]: FAILED su for root by USERNAME
```

### Research Questions (Answer These!)

1. What's the difference between "Failed password for USERNAME" vs "Failed password for invalid user USERNAME"?
2. How would you detect someone trying to enumerate valid usernames via SSH?
3. What does a successful brute force attack look like in the logs?
4. Why is sudo activity important to monitor?

---

## Part 3: Attack Patterns to Detect

### 1. Brute Force Attack

**Signature:**
- Multiple failed login attempts (4625 or "Failed password")
- Same target account OR sequential accounts
- Short time window (seconds to minutes)
- Often from single source IP

**Detection Logic:**
```
IF count(failed_logins) > threshold
   WITHIN time_window
   FOR same_target OR same_source
THEN alert("Possible brute force")
```

**Thresholds to Consider:**
- 5+ failures in 1 minute = likely automated
- 10+ failures in 5 minutes = definite concern
- 100+ failures = active attack

### 2. Password Spraying

**Signature:**
- Failed logins across MANY accounts
- Same password attempted (you won't see this, but pattern is visible)
- Low failures per account (often just 1-2)
- Same source IP or small IP range

**Detection Logic:**
```
IF count(DISTINCT target_users) > threshold
   WITH failed_logins
   FROM same_source
   WITHIN time_window
THEN alert("Possible password spray")
```

### 3. Credential Stuffing

**Signature:**
- Mix of successes and failures
- Many different accounts
- Automated timing patterns
- Often from rotating IPs (proxies)

### 4. Impossible Travel

**Signature:**
- Same user logs in from geographically distant locations
- Time between logins is too short for travel
- Example: NYC login, then London login 10 minutes later

**Detection Logic:**
```
IF same_user
   AND distance(location1, location2) > threshold
   AND time_difference < travel_time_possible
THEN alert("Impossible travel detected")
```

### 5. Off-Hours Activity

**Signature:**
- Logins outside normal business hours
- Especially concerning for privileged accounts
- Weekend activity for accounts that never work weekends

### 6. Lateral Movement Indicators

**Signature:**
- LogonType 3 (Network) between workstations
- New source IPs for a user
- Sequential access to multiple systems
- Service accounts logging in interactively

---

## Part 4: Normalized Event Schema

When you parse different log formats, normalize them to a common structure:

```javascript
{
  // Core fields (required)
  "timestamp": "2024-01-15T14:32:18.000Z",  // ISO 8601 format
  "event_type": "logon_success",             // logon_success, logon_failure, logoff, privilege_escalation
  "source_type": "windows_security",         // windows_security, linux_auth, ssh
  
  // Identity fields
  "username": "jsmith",
  "domain": "CORPORATE",                     // null for Linux
  "source_ip": "192.168.1.105",
  "source_hostname": "REMOTE-PC",
  
  // Target fields  
  "target_hostname": "WORKSTATION01",
  "target_ip": "192.168.1.50",
  
  // Authentication details
  "logon_type": "remote_interactive",        // interactive, network, remote_interactive, service, etc.
  "auth_method": "password",                 // password, publickey, kerberos, ntlm
  "failure_reason": null,                    // null for success, reason string for failures
  
  // Metadata
  "raw_event_id": "4624",                    // Original event ID
  "raw_message": "...",                      // Original log line (for debugging)
  
  // Analysis fields (you'll populate these)
  "risk_score": 0,                           // 0-100 calculated risk
  "risk_factors": [],                        // Array of reasons for risk score
  "tags": []                                 // Custom tags: ["brute_force", "off_hours", etc.]
}
```

---

## Part 5: MITRE ATT&CK Mapping (Bonus)

Map your detections to the MITRE ATT&CK framework for extra interview points:

| Detection | Technique ID | Technique Name |
|-----------|--------------|----------------|
| Brute force | T1110.001 | Brute Force: Password Guessing |
| Password spray | T1110.003 | Brute Force: Password Spraying |
| Credential stuffing | T1110.004 | Brute Force: Credential Stuffing |
| RDP logon | T1021.001 | Remote Services: RDP |
| SSH logon | T1021.004 | Remote Services: SSH |
| Lateral movement | T1021 | Remote Services |
| Valid accounts | T1078 | Valid Accounts |

---

## Your Assignment

Before writing any code:

1. **Answer all the research questions** in Parts 1 and 2
2. **Find sample logs online** - Search for "sample Windows security event log" and "sample auth.log"
3. **Draw out your data flow** - How will logs go from raw text to analyzed events?
4. **Define your thresholds** - What numbers will you use for detection?

Document your answers - this becomes part of your portfolio!

---

## Resources

- [Windows Security Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Linux auditd documentation](https://linux.die.net/man/8/auditd)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma) - Great detection rule examples
