<#
.SYNOPSIS
    Wazuh Active Response Script for Hypothetical ToolShell Zero-Day Mitigation (PowerShell)

.DESCRIPTION
    This script is designed to be triggered by Wazuh rules (e.g., rule IDs 100001-100005, and potentially new network rules).
    It attempts to mitigate the hypothetical threat by:
    1. Logging the incident details.
    2. Identifying and terminating suspicious processes.
    3. Quarantining suspicious files.
    4. Blocking the source IP address if provided and valid.

.PARAMETER AgentID
    The ID of the Wazuh agent that triggered the alert.

.PARAMETER RuleID
    The ID of the Wazuh rule that triggered the alert.

.PARAMETER RuleLevel
    The severity level of the triggered rule.

.PARAMETER FullLog
    The entire log line that triggered the alert.

.PARAMETER SourceIP
    The source IP address (if applicable).

.PARAMETER ProgramName
    The name of the active response program (e.g., 'active-response').

.NOTES
    IMPORTANT: This is a GENERIC and HYPOTHETICAL script.
    - Always test active response scripts thoroughly in a non-production environment.
    - Real-world mitigation requires specific knowledge of the exploit and its artifacts.
    - Running commands like 'Stop-Process' or 'Move-Item' can disrupt legitimate system operations if not precise.
    - This script assumes the 'FullLog' contains key-value pairs that can be extracted via regex.
    - IP blocking rules created by this script are persistent until manually removed or a cleanup mechanism is implemented.
#>

param(
    [string]$AgentID,
    [string]$RuleID,
    [string]$RuleLevel,
    [string]$FullLog,
    [string]$SourceIP,
    [string]$ProgramName
)

# Define log file for this script's actions
# Adjust this path if your Wazuh agent is installed in a different location
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response.log"

# Function to log script actions
function Log-Action {
    param(
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    $LogEntry = "$Timestamp - Agent: $AgentID, Rule: $RuleID, Level: $RuleLevel - $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Host $LogEntry # Also print to stdout so Wazuh manager can capture it
}

Log-Action "Active response triggered for Rule ID: $RuleID"
Log-Action "Full log: $FullLog"

# --- Mitigation Logic ---

# Scenario 1: Process-related rules (100001, 100003, 100004)
# Attempt to identify and terminate the suspicious process.
if ($RuleID -eq "100001" -or $RuleID -eq "100003" -or $RuleID -eq "100004") {
    Log-Action "Attempting to identify and terminate suspicious process..."

    # Extract the process image/path from the full log using regex
    # Sysmon Event ID 1 (Process Creation) typically has 'Image' field
    $ProcessPathMatch = [regex]::Match($FullLog, '"Image":\s*"([^"]+)"')
    $ProcessPath = if ($ProcessPathMatch.Success) { $ProcessPathMatch.Groups[1].Value } else { $null }

    if (-not [string]::IsNullOrEmpty($ProcessPath)) {
        Log-Action "Identified potential malicious process path: $ProcessPath"

        # Get process by path (more reliable than just name for unique identification)
        # Using WMI as Get-Process doesn't directly support path filtering
        try {
            $ProcessesToKill = Get-WmiObject Win32_Process | Where-Object { $_.ExecutablePath -eq $ProcessPath }

            if ($ProcessesToKill.Count -gt 0) {
                Log-Action "Found $($ProcessesToKill.Count) active processes matching path: $ProcessPath. Attempting to kill processes."
                foreach ($Proc in $ProcessesToKill) {
                    try {
                        Stop-Process -Id $Proc.ProcessId -Force -ErrorAction Stop
                        Log-Action "Successfully killed process with PID: $($Proc.ProcessId) (Name: $($Proc.Name))"
                    } catch {
                        Log-Action "Failed to kill process with PID: $($Proc.ProcessId) - Error: $($_.Exception.Message)"
                    }
                }
            } else {
                Log-Action "No active processes found matching path: $ProcessPath."
            }
        } catch {
            Log-Action "Error querying processes via WMI: $($_.Exception.Message)"
        }
    } else {
        Log-Action "Could not extract process path from log for process termination."
    }
}

# Scenario 2: File-related rules (100002, 100005)
# Attempt to quarantine the suspicious file.
if ($RuleID -eq "100002" -or $RuleID -eq "100005") {
    Log-Action "Attempting to quarantine suspicious file..."

    # Extract the target filename from the full log using regex
    # Sysmon Event ID 11 (File Creation) typically has 'TargetFilename' field
    $TargetFileMatch = [regex]::Match($FullLog, '"TargetFilename":\s*"([^"]+)"')
    $TargetFile = if ($TargetFileMatch.Success) { $TargetFileMatch.Groups[1].Value } else { $null }

    if (-not [string]::IsNullOrEmpty($TargetFile) -and (Test-Path -Path $TargetFile -PathType Leaf)) {
        Log-Action "Identified potential malicious file: $TargetFile. Attempting to quarantine."

        # Define quarantine directory
        # Adjust this path if your Wazuh agent is installed in a different location
        $QuarantineDir = "C:\Program Files (x86)\ossec-agent\active-response\quarantine"

        try {
            # Create quarantine directory if it doesn't exist
            if (-not (Test-Path -Path $QuarantineDir -PathType Container)) {
                New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
                Log-Action "Created quarantine directory: $QuarantineDir"
            }

            $FileName = Split-Path -Path $TargetFile -Leaf
            $QuarantinedPath = Join-Path -Path $QuarantineDir -ChildPath "$($FileName)_$(Get-Date -Format 'yyyyMMddHHmmss')" # Append timestamp

            Move-Item -Path $TargetFile -Destination $QuarantinedPath -Force -ErrorAction Stop
            Log-Action "Successfully quarantined file: $TargetFile to $QuarantinedPath"
        } catch {
            Log-Action "Failed to quarantine file: $TargetFile - Error: $($_.Exception.Message)"
        }
    } else {
        Log-Action "Could not extract target file path from log or file does not exist for quarantine."
    }
}

# Scenario 3: IP Blocking
# This section will block the SourceIP if it's a valid IP address.
# This would typically be triggered by rules that identify a malicious source IP.
# For example, if you have a rule for failed login attempts from a specific IP, or
# a network-based rule detecting malicious traffic from an IP.
if (-not [string]::IsNullOrEmpty($SourceIP)) {
    # Basic validation for IPv4 address format
    if ($SourceIP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        Log-Action "Attempting to block source IP: $SourceIP"
        $RuleName = "Wazuh_AR_Block_ToolShell_IP_$($SourceIP.Replace('.', '_'))_$(Get-Date -Format 'yyyyMMddHHmmss')"

        try {
            # Check if a rule for this IP already exists to avoid duplicates
            $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
            if ($ExistingRule) {
                Log-Action "Firewall rule for IP $SourceIP already exists with name '$RuleName'. Skipping."
            } else {
                New-NetFirewallRule -DisplayName $RuleName `
                                    -Direction Inbound `
                                    -Action Block `
                                    -RemoteAddress $SourceIP `
                                    -Profile Any `
                                    -Force `
                                    -ErrorAction Stop | Out-Null
                Log-Action "Successfully blocked inbound traffic from IP: $SourceIP with rule '$RuleName'."

                # Optionally, block outbound traffic as well
                New-NetFirewallRule -DisplayName "$RuleName (Outbound)" `
                                    -Direction Outbound `
                                    -Action Block `
                                    -RemoteAddress $SourceIP `
                                    -Profile Any `
                                    -Force `
                                    -ErrorAction Stop | Out-Null
                Log-Action "Successfully blocked outbound traffic to IP: $SourceIP with rule '$RuleName (Outbound)'."
            }
        } catch {
            Log-Action "Failed to block IP $SourceIP - Error: $($_.Exception.Message)"
        }
    } else {
        Log-Action "Invalid SourceIP format received: $SourceIP. Skipping IP blocking."
    }
} else {
    Log-Action "No SourceIP provided for IP blocking."
}


Log-Action "Active response script finished."
