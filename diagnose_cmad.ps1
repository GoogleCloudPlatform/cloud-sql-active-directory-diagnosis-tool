function Test-Admin {
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-CheckAvailableDCs {
param(
 [array]$OnPremIPAddresses
)
$LogStringBuilder = [System.Text.StringBuilder]::new()
$AvailableDCs = @()
$UnreachableDCs = @()
$Status = ""
foreach ($OnPremIPAddress in $OnPremIPAddresses) {
 $IsSuccess = Test-Connection -ComputerName $OnPremIPAddress -Quiet
 if ($IsSuccess) {
     $AvailableDCs += $OnPremIPAddress
 } else {
     $UnreachableDCs += $OnPremIPAddress
 }
}

if ($UnreachableDCs.Count -gt 0) {
 $Status = "WARNING"
 [void]$LogStringBuilder.AppendLine("Failed to ping domain controllers at following IP addresses: {0}" -f ($UnreachableDCs -join ', '))
} else {
 $Status = "PASSED"
}

[void]$LogStringBuilder.Append('Status: {0}' -f $Status)

return $AvailableDCs, $LogStringBuilder.ToString()
}

function Test-CheckPort {

[cmdletbinding(
DefaultParameterSetName = '',
ConfirmImpact = 'low'
)]
param(
 [array]$OnPremIPAddresses,
 [array]$Ports,
 [string]$Protocol
)
Begin {
 $ErrorActionPreference = "SilentlyContinue"
 $ClosedPorts = @()
 $LogStringBuilder = [System.Text.StringBuilder]::new()
 $WarningState = $false
 $FailedState = $false
 $ConnectionTimeout = 1800
}
Process {
 ForEach ($IPAddress in $OnPremIPAddresses) {
     ForEach ($Port in $Ports) {
         If ($Protocol -eq "TCP") {
             #Create object for connecting to port on computer
             $TCPObject = new-Object system.Net.Sockets.TcpClient
             #Connect to remote machine's port
             $Connect = $TCPObject.BeginConnect($IPAddress,$Port,$null,$null)
             #Configure a timeout before quitting
             $Wait = $Connect.AsyncWaitHandle.WaitOne($ConnectionTimeout, $false)
             #If timeout
             If(!$Wait) {
                 #Close connection
                 $TCPObject.Close()
                 $ClosedPorts += $Port
             } Else {
                 $Error.Clear()
                 $TCPObject.EndConnect($Connect) | out-Null
                 #If error
                 If($Error[0]){
                     $Failed = $true
                 }
                 #Close connection
                 $TCPObject.Close()
                 #If unable to query port due to failure
                 If($Failed){
                     $ClosedPorts += $Port
                 }
             }
             #Reset failed value
             $Failed = $null
         }
         If ($Protocol -eq "UDP") {
             #Create object for connecting to port on computer
             $UDPObject = new-Object system.Net.Sockets.Udpclient
             #Set a timeout on receiving message
             $UDPObject.Client.ReceiveTimeout = $ConnectionTimeout
             #Connect to remote machine's port
             $UDPObject.Connect("$IPAddress",$Port)
             #Sends a message to the host to which you have connected.
             $Message = new-object system.text.asciiencoding
             $Byte = $Message.GetBytes("$(Get-Date)")
             [void]$UDPObject.Send($Byte,$Byte.length)
             #IPEndPoint object will allow us to read datagrams sent from any source.
             $RemoteEndpoint = New-Object system.net.ipendpoint([System.Net.IPAddress]::Any,0)
             Try {
                 #Blocks until a message returns on this socket from a remote host.
                 Write-Verbose "Waiting for message return"
                 $ReceiveBytes = $UDPObject.Receive([ref]$RemoteEndpoint)
                 [string]$ReturnData = $Message.GetString($ReceiveBytes)
                 If ($ReturnData) {
                    #Connection Successful
                     $UDPObject.close()
                 }
             } Catch {
                 If ($Error[0].ToString() -match "\bRespond after a period of time\b") {
                     #Close connection
                     $UDPObject.Close()
                     #Make sure that the host is online and not a false positive that it is open
                     If (Test-Connection -comp $IPAddress -count 1 -quiet) {
                         #Connection Open
                     } Else {
                         <#
                         It is possible that the host is not online or that the host is online,
                         but ICMP is blocked by a firewall and this port is actually open.
                         #>
                         #Host maybe unavailable
                         $ClosedPorts += $Port
                     }
                 } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) {
                     #Close connection
                     $UDPObject.Close()
                     #Connection Timeout
                     $ClosedPorts += $Port
                 } Else {
                     $UDPObject.close()
                 }
             }
         }
     }

     # Generate logs for current on-prem domain controller
     if ($ClosedPorts.Count -gt 0) {
         [void]$LogStringBuilder.AppendLine("Protocol: {0}. IP Address: {1}. Closed/unreachable ports: {2}" -f ($Protocol, $IPAddress, ($ClosedPorts -join ', ')))
         $WarningState = $true
         foreach ($ClosedPort in $ClosedPorts) {
             if (!($RPCPorts -Contains $ClosedPort)) {
                 $FailedState = $true
                 break
             }
         }
     }

     # Reset closed ports for next on-prem domain controller's port check.
     $ClosedPorts = @()
 }

 [void]$LogStringBuilder.Append('Status ({0} port check): ' -f $Protocol)
 if ($FailedState) {
     [void]$LogStringBuilder.AppendLine('FAILED')
 } else {
     if ($WarningState) {
         [void]$LogStringBuilder.AppendLine('WARNING')
     } else {
         [void]$LogStringBuilder.AppendLine('PASSED')
     }
 }
}
End {
 return $LogStringBuilder.ToString()
}
}

function Test-CheckDCReplication {
param (
 [string]$OnPremDomainName
)
$Status = "FAILED"
$LogStringBuilder = [System.Text.StringBuilder]::new()
$ReplicationResults = Get-ADReplicationFailure -Target localhost -errorAction SilentlyContinue
if ($ReplicationResults -eq $null) {
 $Status = "PASSED"
} else {
 $FoundError = $false
 foreach ($Result in $ReplicationResults) {
     if ($Result.FailureCount -gt 0) {
         $FoundError = $true
         [void]$LogStringBuilder.AppendLine('Replication failures found on server: {0}' -f $Result.Server)
     }
 }

 if ($FoundError -eq $false) {
    $Status = "PASSED"
 }
}

[void]$LogStringBuilder.Append('Status: {0}' -f $Status)

return $LogStringBuilder.ToString()
}

function Test-ADAccountHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SamAccountName
    )
    
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $Status = "ACCOUNT_NOT_FOUND"

    # Attempt to retrieve the user, suppressing the 'object not found' error
    $User = Get-ADUser -Identity $SamAccountName -Properties Enabled, LockedOut, PasswordExpired, lockoutTime -ErrorAction SilentlyContinue

    if ($User -ne $null) {
        # Account Exists
        $Status = "PASSED"

        # 2. Check Enabled/Disabled Status
        if (-not $User.Enabled) {
            $Status = "Account is administratively disabled."
            [void]$LogStringBuilder.AppendLine($Status)
        } 

        # 3. Check Locked Out Status
        if ($User.LockedOut) {
            # Convert the large integer AD timestamp to a readable datetime
            $LockoutTimestamp = [datetime]::FromFileTime($User.lockoutTime)
            
            # Update status only if not already failed due to disability
            if ($Status -eq "PASSED") {
                 $Status = "Account is locked out since $($LockoutTimestamp)."
            }
            [void]$LogStringBuilder.AppendLine("Locked Out Time: $($LockoutTimestamp)")
        }

        # 4. Check Password Expiration
        if ($User.PasswordExpired) {
            # Update status only if not already failed/locked
            if ($Status -eq "PASSED") {
                $Status = "WARNING: Password has expired."
            }
            [void]$LogStringBuilder.AppendLine("Password Expired: True")
        }
        
    } else {
        # Account Not Found or Query Failed
        $Status = "Account '$SamAccountName' was not found or query failed."
        [void]$LogStringBuilder.AppendLine($Status)
    }
    
    # Ensure final log message is set
    if ($Status -eq "PASSED") {
        [void]$LogStringBuilder.AppendLine("Account state is OK (Enabled, Not Locked, Password Not Expired).")
    }

    [void]$LogStringBuilder.Append('Status: {0}' -f $Status)
    return $LogStringBuilder.ToString()
}

function Test-OUExists {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OrganizationalUnitDN
    )
    
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $Status = "FAILED"
    try {
        $OU = Get-ADOrganizationalUnit -Identity $OrganizationalUnitDN -ErrorAction Stop
        
        # If the command succeeds, the OU exists
        [void]$LogStringBuilder.AppendLine("OU '$OrganizationalUnitDN' exists.")
        $Status = "PASSED"
    } catch {
        # If an error occurs, check if it's the specific 'object not found' error
        if ($_.Exception.Message -match "Cannot find an object with identity") {
            [void]$LogStringBuilder.AppendLine("OU '$OrganizationalUnitDN' does not exist.")
        } else {
            # Handle other errors (e.g., connectivity, permissions)
            [void]$LogStringBuilder.AppendLine("ERROR: Failed to query AD. $($_.Exception.Message)")
        }
    }

    [void]$LogStringBuilder.Append('Status: {0}' -f $Status)
    return $LogStringBuilder.ToString()
}

Clear-Host


$RunAsAdmin = $null
# Check Script is running with Elevated Privileges
if ((Test-Admin) -eq $true)  {
Write-Output 'Script is running as Administrator.'

} else {
$RunAsAdmin = Read-Host -Prompt 'Run script as Administrator? (y/yes or n/no)'
if ($RunAsAdmin -ieq "y" -or $RunAsAdmin -ieq "yes") {
 Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
 exit
}
}

$OnPremDomainName = Read-Host -Prompt 'Input your on-prem domain name (Example: my-onprem-domain.com)'
$AdminAccount = Read-Host -Prompt 'Input the AD admin account used to enable Customer-managed Active Directory (Example: myadmin)'
$OU = Read-Host -Prompt 'Input the OU used to enable Customer-managed Active Directory (Example: OU=cloud,DC=my-onprem-domain,DC=com)'

# Get IP addresses for all on-prem domain controllers in the AD forest
$OnPremIPAddresses = $null
$OnPremIPAddresses = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $OnPremDomainName } | Select -ExpandProperty IPV4Address

if ($OnPremIPAddresses -eq $null) {
Write-Output ("No on-prem domain controllers found in the given on-prem domain name. Verify that this script is running on a domain controller of the on-prem domain: {0}. Exiting..." -f $OnPremDomainName)
Exit
}

# Check for available on-prem domain controllers
Write-Host -ForegroundColor Yellow "`n`nChecking for available on-prem domain controllers..."
$OnPremIPAddresses, $CheckDCResult = Test-CheckAvailableDCs -OnPremIPAddresses $OnPremIPAddresses
Write-Output $CheckDCResult
# End of check for available on-prem domain controllers

# Check for ports
$TCPPorts = @(53, 88, 135, 389, 445, 464)
Write-Host -ForegroundColor Yellow "`n`nChecking TCP and UDP ports for on-prem domain controllers... (This operation can take up to a minute)"
$TCPResult = Test-CheckPort -OnPremIPAddresses $OnPremIPAddresses -Ports $TCPPorts -Protocol "TCP"
Write-Output $TCPResult
$UDPResult = Test-CheckPort -OnPremIPAddresses $OnPremIPAddresses -Ports 53, 88, 389, 464 -Protocol "UDP"
Write-Output $UDPResult
# End of check for ports

# Check for domain controller replication
if ($OnPremIPAddresses.Count -gt 1) {
Write-Host -ForegroundColor Yellow "`n`nChecking domain controller replication..."
$DCReplicationResult = Test-CheckDCReplication -OnPremDomainName $OnPremDomainName
Write-Output $DCReplicationResult
} else {
Write-Host -ForegroundColor Yellow "`n`nSkipping domain controller replication check as only one available on-prem domain controller was found..."
}
# End of check for domain controller replication

# Check the AD admin account
Write-Host -ForegroundColor Yellow "`n`nChecking AD admin account status..."
Test-ADAccountHealth -SamAccountName $AdminAccount
# End of check for AD admin account

# Check the OU
Write-Host -ForegroundColor Yellow "`n`nChecking if OU exists..."
Test-OUExists -OrganizationalUnitDN $OU
# End of check for OU


Write-Host -ForegroundColor Yellow ("`n`nActive Directory diagnosis complete. Refer to the following doc on how to resolve any of the above failures - {0}" -f "https://cloud.google.com/sql/docs/sqlserver/ad-diagnosis-tool") 
