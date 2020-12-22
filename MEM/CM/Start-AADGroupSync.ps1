<#
    .SYNOPSIS
    This script will sync a local on prem AD group with an AAD Group or M365 group. 
    .DESCRIPTION
    
    .EXAMPLE
    Start-AADGroupSync -AADGroupName examplegroup -CertificateThumbprint Thumbprint  -ApplicationId AADAppID -Tenant TenantObjectID
    .NOTES
    
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    $AADGroupName,
    $CertificateThumbprint,
    $AADAppID,
    $TenantID
)



#Check Prereqs
If(-not (Get-Module ActiveDirectory)) {
    Write-Error "ActiveDirectory PowerShell Module is not present. "
}
If(-not ((Get-Module Az.Accounts) -or (Get-Module Az.Resources))) {
    Write-Error "Az.Accounts or Az.Resources PowerShell Module is not present. "
}
If(-not (Get-Module AzureAD)) {
    Write-Error "AzureAD PowerShell Module is not present. "
}


try {
    Write-Verbose "Trying to connect to AAD..."
    Connect-AzAccount -CertificateThumbprint $CertificateThumbprint -ApplicationId $AADAppID -Tenant $TenantID

} catch {
    Write-Error "Failed to connect to AAD. Errormessage is: $($_.Exception.Message)"
}

function Start-AADGroupSync {
    param (
        [CmdletBinding()]
            [Parameter(Mandatory=$true)]
            $AADGroupName
    )

    try {
        Write-Verbose "Getting ADGroupMembers"
        $AADGroupMembers = Get-AzADGroupMember -GroupDisplayName $AADGroupName
    } catch {
        Write-Warning "Failed to get AADGroupMembers:" $_.Exception.Message
    }
    try {
        Write-Verbose "Getting ADGroupMembers"
        $ADGroupMembers = Get-ADGroupMember -identity $AADGroupName
    } catch {
        Write-Warning "Failed to get ADGroupMembers:" $_.Exception.Message
    }
    #Adding UPN to the object
    $ADGroupMembers = $ADGroupMembers | Foreach-object {Get-ADUser $_.Samaccountname -Properties UserPrincipalName} 
    If($ADGroupMembers) {
        Write-Host "ADGroupMember is not empty"
        $Differences = Compare-Object -ReferenceObject $AADGroupMembers.Userprincipalname -DifferenceObject $ADGroupMembers.UserprincipalName
        If($Differences) {
            Foreach ($Difference in $Differences) {
                Write-Output "Processing: $($Difference.InputObject)"
                If($Difference.SideIndicator -eq "<=") {
                    Write-Output "User: $($Difference.InputObject) only exists in AADGroup. Sync it."
                    try {
                           Add-ADGroupMember -Identity $AADGroupName -Members (Get-ADUser -Filter "userprincipalname -eq '$($Difference.InputObject)'")
                           $AddedtoADGroup++
                           
                    } catch {
                            Write-Warning "Could not add user $($Difference.InputObject) to Onprem AD Group. Errormessage: $($_.Exception.Message) "
                    }
                } else {
                    Write-Output "User: $($Difference.InputObject) only exists in onprem AD. Remove it?"
                    Remove-ADGroupMember -Identity $AADGroupName -Members (Get-ADUser -Filter "userprincipalname -eq '$($Difference.InputObject)'")
                    $RemovedFromADGroup++
                    
                }
            }
        } else {
            Write-Output "Onprem group is synched. "
        }
    } else {
        Write-Host "ADGroupMember is empty.Add all members from AAD"
        $AADGroupMembers | Foreach-Object {Add-ADGroupMember -identity  $AADGroupName -Members (Get-ADUser -Filter "userprincipalname -eq '$($_.Userprincipalname)'")}
    }
    
    Write-Output "Added to ADGroup: $($AddedToADGroup)"
    Write-Output "Removed from ADGroup: $($RemovedFromADGroup)"
}

$AddedToADGroup = 0 
$RemovedFromADGroup = 0
Connect-AzAccount -CertificateThumbprint $CertificateThumbprint  -ApplicationId $AADAppID -Tenant $TenantID | Out-Null
Start-AADGroupSync -AADGroupName $AADGroupName

Disconnect-AzAccount | out-null

