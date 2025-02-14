# Windows Security Monitoring & Analysis Script

This repository contains a comprehensive PowerShell script for monitoring and analyzing key Windows Security events. It correlates notable events with the [MITRE ATT&CK](https://attack.mitre.org/) framework, helping security teams identify suspicious behavior such as:

- Auto-start services located in non-standard directories  
- Privileged logons (Event ID 4672)  
- Failed login attempts (Event ID 4625)  
- New process creations (Event ID 4688)  
- Newly installed or modified services (Event ID 4697 / 7045)  

## Contents

- **`WindowsSecurityAnalysis.ps1`**: Primary script offering three main analysis modes:
  1. **Analyze Auto-Starting Services**  
  2. **Monitor Privileged & Failed Logons, and Process Creations**  
  3. **Detect Newly Installed or Modified Services**  

## Features

- **MITRE ATT&CK Mapping**  
  Associates each detected event ID with relevant MITRE technique(s) for quick reference.  
- **Process Tree Construction**  
  Builds a hierarchical tree (parent-child relationships) for Event 4688 process creation logs.  
- **Anomaly Detection**  
  Basic correlation that highlights potential anomalies (e.g., privileged logon quickly followed by suspicious process creation).  
- **Service Analysis**  
  Identifies auto-start services outside standard directories, performs Authenticode signature checks, and inspects associated processes.  

## Usage

1. **Download or Clone** this repository.  
2. **Open PowerShell as Administrator**. Certain security logs and WMI calls require elevated privileges.  
3. **Run the Script**:  
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope Process
   .\WindowsSecurityAnalysis.ps1

Choose Analysis Mode when prompted:

1: Auto-start service analysis

2: Privileged logons, failed attempts, process creation logs

3: Recently created or modified services


## MITRE ATT&CK Reference
A subset of Event IDs mapped in this script:

4624 → T1078 - Valid Accounts

4625 → T1110 - Brute Force

4672 → T1068 - Privilege Escalation

4688 → T1059 - Command and Scripting Interpreter

4697, 7045 → T1543.003 - Windows Service

## Disclaimer

No Warranty: This script is provided “as is”, without warranty of any kind, either express or implied.
Educational/Testing Purposes: Use at your own risk in test or controlled environments. Consult your own organization’s policies and legal requirements before deploying in production.
Contributing
We welcome improvements, especially around:

Additional MITRE technique mappings
Expanded event filtering
Integration with Get-WinEvent or XML-based queries
Please open an issue or submit a pull request to discuss any changes.
