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
    5. Blocking a predefined list of known malicious IP addresses.

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

# Scenario 3: Dynamic IP Blocking (based on SourceIP from alert)
# This section will block the SourceIP if it's a valid IP address.
if (-not [string]::IsNullOrEmpty($SourceIP)) {
    # Basic validation for IPv4 address format
    if ($SourceIP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        Log-Action "Attempting to block dynamic source IP: $SourceIP"
        $RuleName = "Wazuh_AR_Block_Dynamic_IP_$($SourceIP.Replace('.', '_'))_$(Get-Date -Format 'yyyyMMddHHmmss')"

        try {
            # Check if a rule for this IP already exists to avoid duplicates
            $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
            if ($ExistingRule) {
                Log-Action "Firewall rule for dynamic IP $SourceIP already exists with name '$RuleName'. Skipping."
            } else {
                New-NetFirewallRule -DisplayName $RuleName `
                                    -Direction Inbound `
                                    -Action Block `
                                    -RemoteAddress $SourceIP `
                                    -Profile Any `
                                    -Force `
                                    -ErrorAction Stop | Out-Null
                Log-Action "Successfully blocked inbound traffic from dynamic IP: $SourceIP with rule '$RuleName'."

                New-NetFirewallRule -DisplayName "$RuleName (Outbound)" `
                                    -Direction Outbound `
                                    -Action Block `
                                    -RemoteAddress $SourceIP `
                                    -Profile Any `
                                    -Force `
                                    -ErrorAction Stop | Out-Null
                Log-Action "Successfully blocked outbound traffic to dynamic IP: $SourceIP with rule '$RuleName (Outbound)'."
            }
        } catch {
            Log-Action "Failed to block dynamic IP $SourceIP - Error: $($_.Exception.Message)"
        }
    } else {
        Log-Action "Invalid dynamic SourceIP format received: $SourceIP. Skipping dynamic IP blocking."
    }
} else {
    Log-Action "No dynamic SourceIP provided for dynamic IP blocking."
}

# Scenario 4: Predefined IP Blocking (from IOC list)
# This section will block a predefined list of known malicious IP addresses.
$PredefinedMaliciousIPs = @(
    "107.191.58.76",
    "104.238.159.149",
    "96.9.125.147",
    "103.186.30.186",
    "108.162.221.103",
    "128.49.100.57",
    "154.47.29.4",
    "162.158.14.149",
    "162.158.14.86",
    "162.158.19.169",
    "162.158.90.110",
    "162.158.94.121",
    "162.158.94.72",
    "18.143.202.126",
    "18.143.202.156",
    "18.143.202.185",
    "18.143.202.204",
    "45.40.52.75"
)

Log-Action "Attempting to block predefined malicious IP addresses."

foreach ($ip in $PredefinedMaliciousIPs) {
    Log-Action "Blocking predefined IP: $ip"
    $RuleNameInbound = "Wazuh_AR_Block_Predefined_IP_$($ip.Replace('.', '_'))_Inbound"
    $RuleNameOutbound = "Wazuh_AR_Block_Predefined_IP_$($ip.Replace('.', '_'))_Outbound"

    try {
        # Check if inbound rule already exists
        $ExistingInboundRule = Get-NetFirewallRule -DisplayName $RuleNameInbound -ErrorAction SilentlyContinue
        if (-not $ExistingInboundRule) {
            New-NetFirewallRule -DisplayName $RuleNameInbound `
                                -Direction Inbound `
                                -Action Block `
                                -RemoteAddress $ip `
                                -Profile Any `
                                -Force `
                                -ErrorAction Stop | Out-Null
            Log-Action "Successfully blocked inbound traffic from predefined IP: $ip with rule '$RuleNameInbound'."
        } else {
            Log-Action "Firewall rule for predefined IP $ip (Inbound) already exists with name '$RuleNameInbound'. Skipping."
        }

        # Check if outbound rule already exists
        $ExistingOutboundRule = Get-NetFirewallRule -DisplayName $RuleNameOutbound -ErrorAction SilentlyContinue
        if (-not $ExistingOutboundRule) {
            New-NetFirewallRule -DisplayName $RuleNameOutbound `
                                -Direction Outbound `
                                -Action Block `
                                -RemoteAddress $ip `
                                -Profile Any `
                                -Force `
                                -ErrorAction Stop | Out-Null
            Log-Action "Successfully blocked outbound traffic to predefined IP: $ip with rule '$RuleNameOutbound'."
        } else {
            Log-Action "Firewall rule for predefined IP $ip (Outbound) already exists with name '$RuleNameOutbound'. Skipping."
        }

    } catch {
        Log-Action "Failed to block predefined IP $ip - Error: $($_.Exception.Message)"
    }
}


Log-Action "Active response script finished."
