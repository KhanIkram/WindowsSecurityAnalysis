<#
.SYNOPSIS
    Comprehensive PowerShell Script for Monitoring Auto-Starting Services,
    Privileged Logons, Failed Logons, New Process Creations, and Service Modifications
    with MITRE ATT&CK references.

.DESCRIPTION
    This script analyzes Windows Security events within the past 24 hours (by default)
    or according to user selection. It correlates each Event ID with MITRE ATT&CK techniques,
    displays details about suspicious services, privileged logons, and newly installed
    or modified services, and optionally constructs a process tree for 4688 events.

.NOTES
    Run this script in an elevated PowerShell session for full access to Security events.
    Adjust the MITRE mappings and directory whitelists as needed for your environment.
#>

# Optionally enforce strict mode & stop on error
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#---------------------------
# 1. MITRE ATT&CK Mappings
#---------------------------
$mitreMapping = @{
    # Logon / Authentication Events
    '4624' = @('T1078 - Valid Accounts')               # Successful logon
    '4625' = @('T1110 - Brute Force')                  # Failed logon
    '4634' = @('T1078 - Valid Accounts')               # Logoff
    '4648' = @('T1078 - Valid Accounts')               # Explicit credentials
    '4672' = @('T1068 - Privilege Escalation')         # Special privileges assigned to a logon
    '4768' = @('T1558 - Steal or Forge Kerberos Tickets')

    # Process Creation
    '4688' = @('T1059 - Command and Scripting Interpreter')

    # Service-Related Events
    '4697' = @('T1543.003 - Windows Service')          # Service installed
    '7045' = @('T1543.003 - Windows Service')          # Service creation

    # Group Membership and Account Management
    '4720' = @('T1136 - Create Account')               # User account created
    '4732' = @('T1098 - Account Manipulation')         # User added to local group

    # Other (examples)
    '1003' = @('System Crash or BugCheck - No direct MITRE mapping')
    '8002' = @('Custom event or NTLM usage - No standard MITRE mapping')
    '8004' = @('Custom event or NTLM usage - No standard MITRE mapping')
}

#---------------------------
# 2. Check for Admin Rights
#---------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as Administrator."
    return
}

#---------------------------
# 3. User Selection Prompt
#---------------------------
Write-Host "Select analysis mode:"
Write-Host "1. Analyze Auto-Starting Services and Associated Processes"
Write-Host "2. Monitor Privileged Logons, Logoffs, Failed Login Attempts, and New Process Creations (plus process tree)"
Write-Host "3. Detect New or Modified Services and Associated Processes"

$selection = Read-Host "Enter the number for the desired analysis"

#---------------------------
# 4. Shared Helper Functions
#---------------------------

# Convert well-known SIDs to readable names
function Get-SecurityIDSignificance($sid) {
    switch ($sid) {
        "S-1-5-18" { "Local System" }
        "S-1-5-19" { "Local Service" }
        "S-1-5-20" { "Network Service" }
        default    { "User or domain account" }
    }
}

# Retrieves process name by PID
function Get-ProcessNameByProcessID {
    param([int]$processID)
    try {
        $proc = Get-Process -Id $processID -ErrorAction SilentlyContinue
        if ($proc) {
            return $proc.Name
        } else {
            return "UnknownProcess"
        }
    }
    catch {
        return "UnknownProcess"
    }
}

# Build and display process tree from 4688 events
function Build-ProcessTree($processesByPID) {
    $processTree = @{}

    foreach ($pid in $processesByPID.Keys) {
        $proc = $processesByPID[$pid]
        $parentPID = $proc.CreatorProcessID_Decimal

        if ($parentPID -and $processesByPID.ContainsKey($parentPID)) {
            if (-not $processesByPID[$parentPID].Children) {
                $processesByPID[$parentPID].Children = @()
            }
            $processesByPID[$parentPID].Children += $proc
        }
        else {
            if (-not $processTree[$pid]) {
                $processTree[$pid] = $proc
            }
        }
    }

    function Display-ProcessTree($process, $indent) {
        $processName = Get-ProcessNameByProcessID $process.ProcessID_Decimal
        Write-Host "$indent PID: $($process.ProcessID_Decimal) - Process Name: $processName - Command Line: $($process.ProcessCommandLine)"
        if ($process.Children) {
            foreach ($child in $process.Children) {
                Display-ProcessTree $child ($indent + "    ")
            }
        }
    }

    Write-Host "`nProcess Tree (from Event ID 4688):"
    foreach ($rootProc in $processTree.Values) {
        Display-ProcessTree $rootProc ""
    }
}

# Display child processes for a given Parent PID
function Get-ChildProcessesByParentPID {
    param([int]$ParentPID)

    if ($processesByPID.ContainsKey($ParentPID)) {
        $parentProc = $processesByPID[$ParentPID]
        $parentProcName = Get-ProcessNameByProcessID $ParentPID
        Write-Host "Parent Process (PID: $ParentPID, Name: $parentProcName) - Command Line: $($parentProc.ProcessCommandLine)"

        if ($parentProc.Children) {
            Write-Host "Child Processes of Parent PID ${ParentPID}:"
            foreach ($childProc in $parentProc.Children) {
                $childName = Get-ProcessNameByProcessID $childProc.ProcessID_Decimal
                Write-Host "  PID: $($childProc.ProcessID_Decimal) - Process Name: $childName - Command Line: $($childProc.ProcessCommandLine)"
            }
        }
        else {
            Write-Host "No child processes found for Parent PID $ParentPID."
        }
    }
    else {
        Write-Host "No process found with Parent PID $ParentPID in the collected data."
    }
}

#---------------------------
# 5. Block 1 - Auto-Starting Services
#---------------------------
if ($selection -eq 1) {
    Write-Host "`n[Block 1] Analyzing Auto-Starting Services and Associated Processes..."

    $autoServices = Get-WmiObject -Class Win32_Service | Where-Object { $_.StartMode -eq "Auto" }
    foreach ($service in $autoServices) {
        # Filter out standard Windows / Program Files directories
        if ($service.PathName -notlike "C:\Windows\*" -and 
            $service.PathName -notlike "C:\Program Files\*" -and
            $service.PathName -notlike "C:\Program Files (x86)\*") {

            # Extract the executable path (handle quotes)
            $cleanPath = if ($service.PathName -match '^"([^"]+)"') {
                $matches[1]
            } else {
                ($service.PathName -split ' ')[0]
            }

            # Check the digital signature
            try {
                $signature = Get-AuthenticodeSignature -FilePath $cleanPath -ErrorAction Stop
                Write-Host "Suspicious Auto-Starting Service: $($service.Name) - Path: $cleanPath"
                Write-Host "  Display Name: $($service.DisplayName)"
                Write-Host "  Digital Signature Status: $($signature.Status)"
            }
            catch {
                Write-Host "Error checking signature for service [$($service.Name)] at path [$cleanPath]: $_"
            }

            # Find 4688 events referencing this path in last 24 hours
            $processes = Get-EventLog -LogName Security |
                Where-Object {
                    $_.EventID -eq 4688 -and
                    $_.Message -match [regex]::Escape($cleanPath) -and
                    $_.TimeGenerated -ge (Get-Date).AddHours(-24)
                }

            foreach ($procEvent in $processes) {
                $procDetails = @{
                    ProcessID                = ""
                    ProcessID_Decimal        = ""
                    CreatorProcessID         = ""
                    CreatorProcessID_Decimal = ""
                    ProcessCommandLine       = ""
                    DirectoryPath            = ""
                }
                if ($procEvent.Message -match 'New Process ID:\s+(0x[\da-fA-F]+)') {
                    $procDetails.ProcessID = $matches[1]
                    $procDetails.ProcessID_Decimal = [convert]::ToInt32($procDetails.ProcessID, 16)
                }
                if ($procEvent.Message -match 'Creator Process ID:\s+(0x[\da-fA-F]+)') {
                    $procDetails.CreatorProcessID = $matches[1]
                    $procDetails.CreatorProcessID_Decimal = [convert]::ToInt32($procDetails.CreatorProcessID, 16)
                }
                if ($procEvent.Message -match 'New Process Name:\s+(\S+)') {
                    $procDetails.ProcessCommandLine = $matches[1]
                    $procDetails.DirectoryPath = Split-Path -Path $procDetails.ProcessCommandLine -Parent
                }

                # Look up MITRE references for 4688
                $evtID = '4688'
                [array]$mappedTechniques = $mitreMapping[$evtID] -as [array]
                if (-not $mappedTechniques) { $mappedTechniques = @("No known mapping") }

                Write-Host "Associated Process Creation (Event ID 4688):"
                Write-Host "  Time: $($procEvent.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss"))"
                Write-Host "  Process ID: $($procDetails.ProcessID_Decimal)"
                Write-Host "  Creator Process ID: $($procDetails.CreatorProcessID_Decimal)"
                Write-Host "  Command Line: $($procDetails.ProcessCommandLine)"
                Write-Host "  Directory Path: $($procDetails.DirectoryPath)"
                Write-Host "  MITRE ATT&CK: $($mappedTechniques -join ', ')"
                Write-Host "------------------------------"
            }
            Write-Host "------------------------------"
        }
    }
    Write-Host "Auto-Starting Services and Associated Processes Analysis Complete."

#---------------------------
# 6. Block 2 - Privileged Logons, Failures, Process Creations
#---------------------------
} elseif ($selection -eq 2) {
    Write-Host "`n[Block 2] Monitoring Privileged Logons, Logoffs, Failed Login Attempts, and New Process Creations..."

    # Event IDs of interest
    $eventIDs = 4624,4634,4648,4672,4625,4688,4697,4732,4768,1003,7045,8002,8004,4720

    $eventCounts = @{
        "4624"=0; "4634"=0; "4648"=0; "4672"=0; "4625"=0;
        "4688"=0; "4697"=0; "4732"=0; "4768"=0; "1003"=0;
        "7045"=0; "8002"=0; "8004"=0; "4720"=0
    }

    # Patterns for correlation
    $eventPatterns = @{
        PrivilegedLogons = @{}
        ProcessCreations = @{}
        LogonEvents      = @{}
    }

    # For building a process tree
    $global:processesByPID = @{}

    # Pull from Security log (last 24 hrs for demonstration)
    $events = Get-EventLog -LogName Security |
        Where-Object {
            $_.EventID -in $eventIDs -and
            $_.TimeGenerated -ge (Get-Date).AddHours(-24)
        } |
        Sort-Object TimeGenerated -Descending

    foreach ($ev in $events) {
        $idStr = "$($ev.EventID)"  # string
        $eventCounts[$idStr]++

        # Prepare a hashtable to store extracted details
        $details = @{
            TimeGenerated           = $ev.TimeGenerated
            EventID                 = $ev.EventID
            EventType               = ""
            SecurityID              = ""
            SecurityID_Significance = ""
            AccountName             = ""
            Domain                  = ""
            LogonID                 = ""
            LogonID_Decimal         = ""
            ProcessID               = ""
            ProcessID_Decimal       = ""
            CreatorProcessID        = ""
            CreatorProcessID_Decimal= ""
            ProcessCommandLine      = ""
            DirectoryPath           = ""
            Children                = @()
        }

        # Basic classification
        switch ($ev.EventID) {
            4672 {
                $details.EventType = "Privileged Logon"
                if ($ev.Message -match 'Security ID:\s+(\S+)') {
                    $details.SecurityID = $matches[1]
                    $details.SecurityID_Significance = Get-SecurityIDSignificance($details.SecurityID)
                }
                if ($ev.Message -match 'Account Name:\s+(\S+)') {
                    $details.AccountName = $matches[1]
                }
                if ($ev.Message -match 'Logon ID:\s+(0x[\da-fA-F]+)') {
                    $details.LogonID = $matches[1]
                    $details.LogonID_Decimal = [convert]::ToInt64($details.LogonID, 16)
                }
                if ($ev.Message -match 'Process ID:\s+(0x[\da-fA-F]+)') {
                    $details.ProcessID = $matches[1]
                    $details.ProcessID_Decimal = [convert]::ToInt32($details.ProcessID, 16)
                }
                if (!$eventPatterns.PrivilegedLogons[$details.SecurityID]) {
                    $eventPatterns.PrivilegedLogons[$details.SecurityID] = @()
                }
                $eventPatterns.PrivilegedLogons[$details.SecurityID] += $details
            }
            4624 {
                $details.EventType = "Successful Logon"
                if ($ev.Message -match 'Security ID:\s+(\S+)') {
                    $details.SecurityID = $matches[1]
                    $details.SecurityID_Significance = Get-SecurityIDSignificance($details.SecurityID)
                }
                if ($ev.Message -match 'Account Name:\s+(\S+)') {
                    $details.AccountName = $matches[1]
                }
                if ($ev.Message -match 'Logon ID:\s+(0x[\da-fA-F]+)') {
                    $details.LogonID = $matches[1]
                    $details.LogonID_Decimal = [convert]::ToInt64($details.LogonID, 16)
                }
                if (!$eventPatterns.LogonEvents[$details.SecurityID]) {
                    $eventPatterns.LogonEvents[$details.SecurityID] = @()
                }
                $eventPatterns.LogonEvents[$details.SecurityID] += $details
            }
            4688 {
                $details.EventType = "Process Creation"
                if ($ev.Message -match 'New Process ID:\s+(0x[\da-fA-F]+)') {
                    $details.ProcessID = $matches[1]
                    $details.ProcessID_Decimal = [convert]::ToInt32($details.ProcessID, 16)
                }
                if ($ev.Message -match 'Creator Process ID:\s+(0x[\da-fA-F]+)') {
                    $details.CreatorProcessID = $matches[1]
                    $details.CreatorProcessID_Decimal = [convert]::ToInt32($details.CreatorProcessID, 16)
                }
                if ($ev.Message -match 'New Process Name:\s+(\S+)') {
                    $details.ProcessCommandLine = $matches[1]
                    $details.DirectoryPath = Split-Path -Path $details.ProcessCommandLine -Parent
                }
                if ($ev.Message -match 'Security ID:\s+(\S+)') {
                    $details.SecurityID = $matches[1]
                    $details.SecurityID_Significance = Get-SecurityIDSignificance($details.SecurityID)
                }

                # Store for process tree building
                $global:processesByPID[$details.ProcessID_Decimal] = $details

                if (!$eventPatterns.ProcessCreations[$details.SecurityID]) {
                    $eventPatterns.ProcessCreations[$details.SecurityID] = @()
                }
                $eventPatterns.ProcessCreations[$details.SecurityID] += $details
            }
            default {
                # other events still parsed for MITRE mapping
            }
        }

        # Lookup MITRE references
        [array]$mappedTechniques = $mitreMapping["$($details.EventID)"] -as [array]
        if (-not $mappedTechniques) {
            $mappedTechniques = @("No known mapping")
        }

        # Output event details
        Write-Host "Event ID: $($details.EventID) - Time: $($details.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Host " Type: $($details.EventType)"
        Write-Host " Security ID: $($details.SecurityID) (Significance: $($details.SecurityID_Significance))"
        Write-Host " Account Name: $($details.AccountName)"
        Write-Host " Domain: $($details.Domain)"
        Write-Host " Logon ID (Hex): $($details.LogonID)  (Decimal: $($details.LogonID_Decimal))"
        if ($details.ProcessID) {
            Write-Host " Process ID: $($details.ProcessID_Decimal)"
        }
        if ($details.CreatorProcessID) {
            Write-Host " Creator Process ID: $($details.CreatorProcessID_Decimal)"
        }
        if ($details.ProcessCommandLine) {
            Write-Host " Command Line: $($details.ProcessCommandLine)"
        }
        if ($details.DirectoryPath) {
            Write-Host " Directory Path: $($details.DirectoryPath)"
        }
        Write-Host " MITRE ATT&CK: $($mappedTechniques -join ', ')"
        Write-Host "------------------------------"
    }

    # Summary
    Write-Host "`nSummary of Event Occurrences in the Last 24 Hours:"
    foreach ($k in $eventCounts.Keys) {
        Write-Host " Event ID ${k}: $($eventCounts[$k]) occurrences"
    }

    # Build & display a process tree for 4688 events
    Build-ProcessTree $global:processesByPID

    # Simple anomaly detection (privileged + process creation within 5 minutes)
    Write-Host "`nAnalyzing Patterns for Anomalies..."
    foreach ($secID in $eventPatterns.PrivilegedLogons.Keys) {
        $privilegedEvents = $eventPatterns.PrivilegedLogons[$secID]
        if ($eventPatterns.ProcessCreations.ContainsKey($secID)) {
            $processEvents = $eventPatterns.ProcessCreations[$secID]
        } else {
            $processEvents = @()
        }

        if ($privilegedEvents.Count -gt 1 -or $processEvents.Count -gt 1) {
            Write-Host "Potential Anomaly Detected for Security ID: $secID"
            Write-Host " Account: $($privilegedEvents[0].AccountName)"
            Write-Host " Number of Privileged Logons: $($privilegedEvents.Count)"
            Write-Host " Number of Process Creations: $($processEvents.Count)"
            Write-Host " Timestamps for Privileged Logons: $($privilegedEvents | ForEach-Object { $_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss') } | Out-String)"
            Write-Host " Timestamps for Process Creations: $($processEvents | ForEach-Object { $_.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss') } | Out-String)"

            foreach ($privEvent in $privilegedEvents) {
                foreach ($procEvent in $processEvents) {
                    $timeDiff = (New-TimeSpan -Start $privEvent.TimeGenerated -End $procEvent.TimeGenerated).TotalSeconds
                    if ($timeDiff -gt 0 -and $timeDiff -lt 300) {
                        Write-Host "  - Privileged Logon at $($privEvent.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss'))"
                        Write-Host "    followed by Process Creation at $($procEvent.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss'))"
                        Write-Host "    Interval: $timeDiff seconds"
                        Write-Host "    Process ID: $($procEvent.ProcessID_Decimal), Parent Process ID: $($procEvent.CreatorProcessID_Decimal)"
                    }
                }
            }
            Write-Host "------------------------------"
        }
    }
    Write-Host "Privileged Logons, Logoffs, Failed Login Attempts, and New Process Creations Analysis Complete."

    # Optional: let user query a Parent PID for child processes
    $queryParentPID = Read-Host "`nAnalysis complete. Query child processes of a specific Parent PID? (y/n)"
    if ($queryParentPID -eq 'y') {
        $pidInput = [int](Read-Host "Enter the Parent PID")
        Get-ChildProcessesByParentPID -ParentPID $pidInput
    }

#---------------------------
# 7. Block 3 - New/Modified Services
#---------------------------
} elseif ($selection -eq 3) {
    Write-Host "`n[Block 3] Detecting New or Modified Services and Associated Processes..."

    # 4697, 7045 in last 24 hrs
    $serviceChanges = Get-EventLog -LogName Security |
        Where-Object {
            $_.EventID -in 4697,7045 -and
            $_.TimeGenerated -ge (Get-Date).AddHours(-24)
        } |
        Sort-Object TimeGenerated -Descending

    Write-Host "Recently Installed or Modified Services (last 24 hours):"
    foreach ($evt in $serviceChanges) {
        $evtID = "$($evt.EventID)"
        [array]$mappedTechniques = $mitreMapping[$evtID] -as [array]
        if (-not $mappedTechniques) { $mappedTechniques = @("No known mapping") }

        Write-Host " Event ID: $evtID - Time: $($evt.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Host " $($evt.Message)"
        Write-Host " MITRE ATT&CK: $($mappedTechniques -join ', ')"
        Write-Host "------------------------------"
    }

    # Auto-start services in non-standard dirs
    $autoServices = Get-WmiObject -Class Win32_Service |
        Where-Object {
            $_.StartMode -eq "Auto" -and
            $_.PathName -notlike "C:\Windows\*" -and
            $_.PathName -notlike "C:\Program Files\*" -and
            $_.PathName -notlike "C:\Program Files (x86)\*"
        }

    Write-Host "`nPotential Persistent Auto-Starting Services and Associated Processes:"
    foreach ($service in $autoServices) {
        Write-Host " Service: $($service.Name) - Path: $($service.PathName)"

        $cleanPath = ($service.PathName -split ' ')[0].Trim('"')
        $processes = Get-EventLog -LogName Security |
            Where-Object {
                $_.EventID -eq 4688 -and
                $_.Message -match [regex]::Escape($cleanPath) -and
                $_.TimeGenerated -ge (Get-Date).AddHours(-24)
            }

        foreach ($proc in $processes) {
            Write-Host "  Associated Process Creation (Event ID 4688):"

            $evtID = '4688'
            [array]$mappedTechniques = $mitreMapping[$evtID] -as [array]
            if (-not $mappedTechniques) { $mappedTechniques = @("No known mapping") }

            if ($proc.Message -match 'New Process ID:\s+(0x[\da-fA-F]+)') {
                $procIDHex = $matches[1]
                $procIDDec = [convert]::ToInt32($procIDHex, 16)
                Write-Host "   Process ID: $procIDDec"
            }
            if ($proc.Message -match 'Creator Process ID:\s+(0x[\da-fA-F]+)') {
                $creatorProcIDHex = $matches[1]
                $creatorProcIDDec = [convert]::ToInt32($creatorProcIDHex, 16)
                Write-Host "   Creator Process ID: $creatorProcIDDec"
            }
            if ($proc.Message -match 'New Process Name:\s+(\S+)') {
                Write-Host "   Process Command Line: $($matches[1])"
                Write-Host "   Directory Path: $(Split-Path -Path $($matches[1]) -Parent)"
            }
            Write-Host "   MITRE ATT&CK: $($mappedTechniques -join ', ')"
            Write-Host "------------------------------"
        }
        Write-Host "------------------------------"
    }
    Write-Host "Service Change Detection and Associated Processes Analysis Complete."

#---------------------------
# 8. Invalid Selection
#---------------------------
} else {
    Write-Host "`Invalid selection. Exiting script."
}

Write-Host "`Analysis complete. Please review the output for any unusual findings or patterns."
