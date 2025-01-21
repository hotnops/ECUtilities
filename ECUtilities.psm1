#requires -modules ADSync,ActiveDirectory

function Get-ECUDomainUsersInheritingPermissions {
    param (
        
        [Parameter(Mandatory)]
        [string]$OrganizationalUnit # OU Distinguished Name (e.g., "OU=Users,DC=example,DC=com")
    )

    # Ensure the Active Directory module is loaded
    Import-Module ActiveDirectory -ErrorAction Stop

    # Retrieve all users in the specified OU
    $users = Get-ADUser -Filter * -SearchBase $OrganizationalUnit -Properties DistinguishedName

    if (-not $users) {
        Write-Host "No users found in the specified OU ($OrganizationalUnit)." -ForegroundColor Yellow
        return
    }

    # Function to check if a user is inheriting permissions
    function Is-InheritingPermissions {
        param (
            [Parameter(Mandatory)]
            [string]$UserDN
        )

        try {
            # Get the ACL (Access Control List) for the user object
            $acl = Get-ACL -Path "AD:$UserDN"

            # Check for inherited ACEs (Access Control Entries)
            $inheritedPermissions = $acl.Access | Where-Object { $_.IsInherited -eq $true }

            # Return whether there are any inherited permissions
            return ($inheritedPermissions.Count -gt 0)
        } catch {
            Write-Warning "Failed to retrieve ACL for user"
            return $false
        }
    }

    # Iterate through users and check if they are inheriting permissions
    $usersInheritingPermissions = foreach ($user in $users) {
        if (Is-InheritingPermissions -UserDN $user.DistinguishedName) {
            [PSCustomObject]@{
                Name               = $user.Name
                SamAccountName     = $user.SamAccountName
                DistinguishedName  = $user.DistinguishedName
            }
        }
    }

    $usersInheritingPermissions
}

function Get-ECUDomainUsersPartialSynced {
    param (
        
        [Parameter(Mandatory)]
        [string]$OrganizationalUnit # OU Distinguished Name (e.g., "OU=Users,DC=example,DC=com")
    )

    $allUsers =  Get-ADUser -Filter * -SearchBase $OrganizationalUnit -Properties DistinguishedName

    $onPremisesConnector = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq "AD"}
    $entraConnector = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -ne "AD"}
    $partialUsers = @()

    $allUsers | ForEach-Object {
        $csObject = Get-ADSyncCSObject -DistinguishedName $_.DistinguishedName -ConnectorIdentifier $onPremisesConnector.Identifier
        if ($csObject -ne $null) {
            if ($csObject.ConnectedMVObjectId -ne '00000000-0000-0000-0000-000000000000') {
                $mvObject = Get-ADSyncMVObject -Identifier $csObject.ConnectedMVObjectId
                $skipUser = $false
                $mvObject.Lineage | ForEach-Object {
                    if ($_.ConnectorId -eq $entraConnector.Identifier) {
                        $skipUser = $true
                        return
                    }
                }
                if (-not $skipUser) {
                    $partialUsers += $_
                }
            }
            
        } else {
            Write-Debug "[*] Not projected into metavers"
        }
    }

    $partialUsers

}

function Get-ECUDomainUsersHijacked {
    param (
        
        [Parameter(Mandatory)]
        [string]$OrganizationalUnit # OU Distinguished Name (e.g., "OU=Users,DC=example,DC=com")
    )

    $allUsers =  Get-ADUser -Filter * -SearchBase $OrganizationalUnit -Properties DistinguishedName

    $onPremisesConnector = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq "AD"}
    $entraConnector = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -ne "AD"}
    $hijackedUsers = @()

    $allUsers | ForEach-Object {
        $csObject = Get-ADSyncCSObject -DistinguishedName $_.DistinguishedName -ConnectorIdentifier $onPremisesConnector.Identifier
        if ($csObject -ne $null) {
            if ($csObject.ConnectedMVObjectId -ne '00000000-0000-0000-0000-000000000000') {
                $mvObject = Get-ADSyncMVObject -Identifier $csObject.ConnectedMVObjectId
                $skipUser = $false
                $mvObject.Lineage | ForEach-Object {
                    if ($_.ConnectorId -eq $entraConnector.Identifier -and $mvObject.Attributes.Contains("cloudFiltered")) {
                        $hijackedUsers += $mvObject
                        return
                    }
                }
            }
            
        } else {
            Write-Debug "[*] Not projected into metaverse"
        }
    }

    $hijackedUsers
}

function Export-ECUSyncRules {
    param (
        [Parameter(Mandatory)]
        [string]$OutputFilePath
    )

    $xmlSettings = New-Object System.XML.XmlWriterSettings
    $xmlSettings.Indent = $true
    $xmlSettings.IndentChars = "    "
    try {
        $writer = [System.XML.XMLWriter]::Create($OutputFilePath, $xmlSettings)
    } catch {
        Write-Error "[!] Failed to open XML file for writing. $($_.Exception.Message)"
        return
    }

    $writer.WriteStartDocument()
    $writer.WriteStartElement("SyncRules")

    Get-ADSyncRule | ForEach-Object {
        $_.WriteXml($writer)
    }

    $writer.WriteEndElement()
    $writer.WriteEndDocument()
    $writer.Close()
}



