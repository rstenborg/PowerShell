<#
    .SYNOPSIS
    This script will sync update a local Active Directory group based on user memberships from any Azure AD group. 
    .DESCRIPTION
    The sync is one-way only. Azure -> Active Directory. You could run this as a scheduled task or in an Azure Runbook as a hybrid worker if you would like to.
    .PARAMETER AADGroupNames
    The AzureAD Group name that you want to sync to Active Directory
    .PARAMETER CertificateThumbprint 
    The certificate thumbprint that is used when authenticating to Azure AD.
    .PARAMETER AADAppID
    The registered AzureAD application that is used for authenticating with Azure AD
    .PARAMETER TenantID
    The AzureAD tenant to authenticate to
    .PARAMETER ADGroupPathDN
    The path (DestinguishedName) that should be used when the scripts needs to create groups in Active Directory. This happends when a group exists in AzureAD but not in Active Directory.
    .EXAMPLE
    Start-AADGroupSync -AADGroupName examplegroup -CertificateThumbprint 06578D150BF72660B8D11923051D860000000000  -ApplicationId AADAppID -Tenant TenantObjectID -ADGroupPathDN "OU=Test,DC=domain,DC=local"
    .NOTES
    Script name: Start-AADGroupSync.ps1
    Author:      Robin Stenborg
    Contact:     @robinstenborg
    DateCreated: 2020-12-23
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $True, HelpMessage = "Enter the AzureAD Group name that you want to sync to Active Directory")]
    $AADGroupNames,
    [Parameter(Mandatory = $True, HelpMessage = "Enter the certificate thumbprint that is used when authenticating to Azure AD.")]
    $CertificateThumbprint,
    [Parameter(Mandatory = $True, HelpMessage = "Enter the registered AzureAD application that is used for authenticating with Azure AD")]
    $AADAppID,
    [Parameter(Mandatory = $True, HelpMessage = "Enter the AzureAD tenant to authenticate to")]
    $TenantID,
    [Parameter(Mandatory = $false, HelpMessage = "Enter the path (DestinguishedName) that should be used when the scripts needs to create groups in Active Directory.")]
    $ADGroupPathDN
)

function Write-Log { 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory = $true, 
            ValueFromPipelineByPropertyName = $true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory = $false)] 
        [Alias('LogPath')] 
        [string]$Path = "$env:ProgramData\Start-AADGroupSync.log", 
         
        [Parameter(Mandatory = $false)] 
        [ValidateSet("Error", "Warning", "Info")] 
        [string]$Level = "Info", 
         
        [Parameter(Mandatory = $false)] 
        [switch]$NoClobber 
    ) 
   
        # If the file already exists and NoClobber was specified, do not write to the log. 
        if ((Test-Path $Path) -AND $NoClobber) { 
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
        } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
        elseif (!(Test-Path $Path)) { 
            Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File 
        } 
 
        else { 
            # Nothing to see here yet. 
        } 
 
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Write message to error, Warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
                Write-Error $Message 
                $LevelText = 'ERROR:' 
            } 
            'Warning' { 
                Write-Warning $Message 
                $LevelText = 'Warning:' 
            } 
            'Info' { 
                Write-Verbose $Message 
                $LevelText = 'INFO:' 
            } 
        } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 

}

function Import-RSModule ($Module) {

    # If module is imported say that and do nothing
    if (-not (Get-Module | Where-Object { $_.Name -eq $Module })) {
        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module }) {
            Import-Module $Module -Verbose
        }
        else {
            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $Module | Where-Object { $_.Name -eq $Module }) {
                Install-Module -Name $Module -Force -Verbose -Scope CurrentUser
                Import-Module $Module -Verbose
            }
            else {
                # If module is not imported, not available and not in online gallery then abort
                Write-Log -Level Error -Message "Module $Module not imported, not available and not in online gallery, exiting."
                Throw "Module $Module not imported, not available and not in online gallery, exiting."
                
            }
        }
    }
}


function Start-AADGroupSync {
    param (
        [CmdletBinding()]
        [Parameter(Mandatory = $true)]
        $AADGroupName,
        $ADGroupPath
    )
    Write-Log -Message "Processing $($AADGroupName)"
    $ADGroupMembers = $null
    try {
        Write-Log -Message "Getting AADGroupMembers"
        $AADGroupMembers = Get-AzADGroupMember -GroupDisplayName $AADGroupName 
    }
    catch {
        Write-Log -Level Warning -Message "Failed to get AADGroupMembers for group $($AADGroupName) . Errormessage is:  $($_.Exception.Message)"
        
    }
    Write-Log -Message "Checking if AD Group exists"
    $ADGroup = Get-ADGroup $AADGroupName -ErrorAction SilentlyContinue 
    If (-not ($ADGroup)) {
        If ($ADGroupPath) {
            Write-Log -Level Warning -Message "ADGroup $($AADGroupName) doesnt exist. Trying to create it."
            Try {
                New-ADGroup -Name $AADGroupName -Path $ADGroupPath -Description "Group synched down from AAD." -GroupScope Universal
            }
            catch {
                Write-Log -Level Warning -Message "Could not create ADGroup. Errormessage is: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds 10
            If ((Get-ADGroup -Identity $AADGroupName)) {
                Write-Log -Message "Successfully created ADGroup $($AADGroupName)"
                $global:ADGroupsCreated++
            }
                
                
        }
        else {
            Write-Log -Level Warning -Message "ADGroup $($AADGroupName) doesnt exist. ADGroupPathDN is not set as input parameter, therefore skipping this group." 
        }
    }
    else {
        Write-Log -Message "ADGroup $($AADGroupName) already exists"
    }

    If (Get-ADGroup $AADGroupName) {
        Write-Log -Message "Getting ADGroupMembers"
        $ADGroupMembers = Get-ADGroupMember -identity $AADGroupName -ErrorAction SilentlyContinue
        #Adding UPN to the object
        $ADGroupMembers = $ADGroupMembers | Foreach-object { Get-ADUser $_.Samaccountname -Properties UserPrincipalName } 
        #ADGroupMember is not empty
        If ($ADGroupMembers) {
            #Compare AAD and AD group members
            $Differences = Compare-Object -ReferenceObject $AADGroupMembers.Userprincipalname -DifferenceObject $ADGroupMembers.UserprincipalName
            If ($Differences) {
                Foreach ($Difference in $Differences) {
                    Write-Log -Message "Processing: $($Difference.InputObject)"
                    If ($Difference.SideIndicator -eq "<=") {
                        Write-Log -Message "User: $($Difference.InputObject) only exists in AADGroup. Sync it."
                        try {
                            Add-ADGroupMember -Identity $AADGroupName -Members (Get-ADUser -Filter "userprincipalname -eq '$($Difference.InputObject)'")
                            $global:AddedtoADGroup++
                           
                        }
                        catch {
                            Write-Log -Level Warning -Message "Could not add user $($Difference.InputObject) to Onprem AD Group. Errormessage: $($_.Exception.Message) "
                        }
                    }
                    else {
                        Write-Log -Message "User: $($Difference.InputObject) only exists in onprem AD. Remove it from group. "
                        Remove-ADGroupMember -Identity $AADGroupName -Members (Get-ADUser -Filter "userprincipalname -eq '$($Difference.InputObject)'") -confirm:$false
                        $global:RemovedFromADGroup++
                    
                    }
                }
            }
            else {
            
                Write-Log -Message "Completed processing ADGroup: $($AADGroupName) ."
            }
        }
        else {
            Write-Log -Message "ADGroupMember is empty. Add all members from AAD group."
            $AADGroupMembers | Foreach-Object { Add-ADGroupMember -identity  $AADGroupName -Members (Get-ADUser -Filter "userprincipalname -eq '$($_.Userprincipalname)'") }
            $global:AddedToADGroup += ($AADGroupMembers).Count
        } 
    }
    else {
       
    }

}
Write-Log -Message "--------------------------------------"
Write-log -Message "STARTING SCRIPT."
Write-log -Message "AADGroups to sync: $($AADGroupNames)"
#Check Prereqs
If (-not (Get-Module ActiveDirectory)) {
    Import-Module ActiveDirectory -Scope CurrentUser -Force
}
else {
    if (-not (Get-Module ActiveDirectory -ListAvailable)) {
        Write-Log -Level Error -Message "ActiveDirectory PowerShell Module is not present. Script will exit. "
        Throw "ActiveDirectory PowerShell Module is not present. Script will exit." 
    }
}
Import-RSModule -Module "Az.Accounts"
Import-RSModule -Module "Az.Resources"

#Connect to AAD
try {
    Write-Log -Message "Trying to connect to AAD..."
    Connect-AzAccount -CertificateThumbprint $CertificateThumbprint -ApplicationId $AADAppID -Tenant $TenantID

}
catch {
    Write-Log -Level Error -Message "Failed to connect to AAD. Errormessage is: $($_.Exception.Message)"
    Throw "Failed to connect to AAD. Errormessage is: $($_.Exception.Message)"
}

#Set vars
$global:AddedToADGroup = 0
$global:RemovedFromADGroup = 0
$global:ADGroupsCreated = 0

$AADGroupNames | ForEach-Object { Start-AADGroupSync -AADGroupName $_ -ADGroupPath $ADGroupPathDN }

Write-Log -Message "Users added to ADGroup: $($AddedToADGroup)"
Write-Log -Message "Users removed from ADGroup: $($RemovedFromADGroup)"
Write-Log -Message "AD-Groups created: $($ADGroupsCreated)"
Write-Log -Message "SCRIPT EXERCUTION COMPLETE."
Write-Log -Message "--------------------------------------"

Disconnect-AzAccount | out-null

