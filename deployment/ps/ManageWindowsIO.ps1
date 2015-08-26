##################################################################################
# Define input parameters.
param
(
  [string]$Action = $null,
  [string]$FileFolderName = $null,
  [string]$DestinationName = $null,
  [string]$ReadOnly = $null,
  [string]$Archive = $null,
  [string]$System = $null,
  [string]$Hidden = $null,
  [string]$OwnerDomain = $null,
  [string]$OwnerName = $null,
  [string]$WorkingDirectory = $null
)
cls

##################################################################################
# Output the logo.
"Microsoft Release Management ManageWindowsIO PowerShell Script v12.0"
"Copyright (c) 2013 Microsoft. All rights reserved.`n"

##################################################################################
# Output execution parameters.
"Executing with the following parameters:"
"  Action: $Action"
"  Source file or folder name: $FileFolderName"
"  Destination file or folder name: $DestinationName"
"  Read Only: $ReadOnly"
"  Archive: $Archive"
"  System: $System"
"  Hidden: $Hidden"
"  Owner Domain: $OwnerDomain"
"  Owner Name: $OwnerName"
if ($WorkingDirectory)
{
  "  Working Directory: $WorkingDirectory`n"
}
else
{
  "  Working Directory: (script path)`n"
}

##################################################################################
# Initialize the default script exit code.
$exitCode = 0

##################################################################################
# Format errors to be more verbose.
trap
{
  $e = $error[0].Exception
  $e.Message
  $e.StackTrace
  if ($exitCode -eq 0) { $exitCode = 1 }
}

##################################################################################  
# Get the name of the script executing.
$scriptName = $MyInvocation.MyCommand.Name

##################################################################################  
# Get the path from where the script is executing.
$scriptPath = Split-Path -Parent (Get-Variable MyInvocation -Scope Script).Value.MyCommand.Path

##################################################################################  
# Change the working directory to that from where the script is executing.
Push-Location $scriptPath    

##################################################################################
# Provides help information about this script.
function Show-Help
{
  "USAGE:`n"
  "$scriptName [-Action] <action> [-FileFolderName] filefoldername [ [-DestinationName] <destination> [-ReadOnly] <readonly> [-Archive] <archive> [-System] <system> [-Hidden] <hidden> [-OwnerDomain] <domain> [-OwnerName] <owner> [-WorkingDirectory] <dir>]`n"
  "WHERE:`n"
  "Action`t`t`tAction to be performed"
  "FileFolderName`t`tThe source file(s) or folder to be used for the specified action."
  "DestinationName`t`tOptional. Destination Path or name to perform specified action"
  "ReadOnly`t`tOptional. Allow the user to set or reset the file(s) or folder read-only attribute.+ : Set the flag - : Reset the flag - Any other value : Let the flag as it is "
  "Archive`t`tOptional. Allow the user to set or reset the file(s) or folder archive attribute.+ : Set the flag - : Reset the flag - Any other value : Let the flag as it is "
  "System`t`tOptional. Allow the user to set or reset the file(s) or folder system attribute.+ : Set the flag - : Reset the flag - Any other value : Let the flag as it is "
  "Hidden`t`tOptional. Allow the user to set or reset the file(s) or folder hidden attribute.+ : Set the flag - : Reset the flag - Any other value : Let the flag as it is "
  "OwnerDomain`t`tOptional.Represent the domain of the new owner to affect to the file(s) or folder. If not defined, the user specified will be considered as a local one (i.e. .\localuser)"
  "OwnerName`t`tOptional. Represent the name of the new owner to affect to the file(s) or folder."
  "WorkingDirectory`t`tOptional. Working directory of the executable to run.`n"
}

##################################################################################
# Sets this script's exit code.
function Set-ScriptExitCode
{
  param
  (
    [int]$code = $(throw "The Exit Code must be provided.")
  )

  # Set the exit code within the context of the script using
  # Set-Variable so we can specify the scope. 
  # Otherwise, the value will not be overwritten.
  Set-Variable -Name exitCode -Value $code -Scope "Script"
}


##################################################################################
# Validation of the parameters by action
if (-not $Action -or -not $FileFolderName)
{
  Show-Help
  
  if (-not $Action)
  {
    Write-Host "Action must be specified.`n" -ForegroundColor Red
  }
  
  if (-not $FileFolderName)
  {
    Write-Host "FileFolderName must be specified.`n" -ForegroundColor Red
  }  
  $exitCode = 1
}
if (-not $WorkingDirectory)
{
  $WorkingDirectory = $scriptPath
}

##################################################################################
# Applys the action and returns its exit code.
function Apply-Action
{
  param
  (
    [string]$Action = $(throw "The action must be provided."),
    [string]$FileFolderName = $(throw "The file or folder name must be provided."),
    [string]$DestinationName = $null,
    [string]$ReadOnly = $null,
    [string]$Archive = $null,
    [string]$System = $null,
    [string]$Hidden = $null,
    [string]$OwnerDomain = $null,
    [string]$OwnerName = $null,
    [string]$WorkingDirectory = $null
  )

  $Action = $Action.ToLower()
  try
  {
    
    # First validate if FileFolderName is null or empty
    if ([string]::IsNullOrEmpty($FileFolderName.Trim()))
    {            
       $(throw "FileFolderName cannot be empty.")        
    }

    ##################################################################################
    # Process the action
    # Create a folder
    if ($Action -eq "create")
    {
      
      # When creating, we first validate if the folder already exists.
      if (-not (Test-Path -PathType Container -Path $FileFolderName))
      {
        # Try to create the folder specified
        New-Item -ItemType directory -path $FileFolderName

        # Check if the folder was created successfully
        if (-not (Test-Path -PathType Container -Path $FileFolderName))
        {
          $(throw "The folder could not be created.")
        }
      }
    }
    # Delete a file or a folder
    elseif ($Action -eq "delete")
    {
      # We determine if the specified is a file or a folder
      if ((Test-Path -PathType Container -Path $FileFolderName) -or
          (Test-Path -PathType Leaf -Path $FileFolderName))
      {
        Remove-Item -Path $FileFolderName -Recurse -Force
        if ((Test-Path -PathType Container -Path $FileFolderName) -or
            (Test-Path -PathType Leaf -Path $FileFolderName))
        {
          $(throw "The folder or file could not be deleted.")
        }
      }
    }
    # Rename a file or a folder
    elseif ($Action -eq "rename")
    {
      if ([string]::IsNullOrEmpty($DestinationName))
      {
        $(throw "The destination must be specified.")
      }

      # We check if the destination contains the folder. If it is, we ensure it correspond to the source and remove it
      $foldersDestination = $DestinationName.Split([System.IO.Path]::DirectorySeparatorChar)
      if ($destinationFolders.Count -gt 1)
      {
        $foldersSource = $FileFolderName.Split([System.IO.Path]::DirectorySeparatorChar)
        $parentFolderSource = [string]::Join("\", $foldersSource, 0, $foldersSource.Count - 1)
        $foldersDestination = $DestinationName.Split([System.IO.Path]::DirectorySeparatorChar)
        $parentFolderDestination = [string]::Join("\", $foldersDestination, 0, $foldersDestination.Count - 1)
        if ($parentFolderSource -ne $parentFolderDestination)
        {
          $(throw "The source and destination path must correspond for the renaming to work.")
        }
        $DestinationName = $foldersDestination[$foldersDestination.Count - 1]
      }

      # We determine if the source is a folder
      # We cannot use Rename-Item for folder since it will not work when the folder is empty. Use Move-Item instead.
      if (Test-Path -PathType Container -Path $FileFolderName)
      {
        # We split the source path in an array
        $foldersSource = $FileFolderName.Split([System.IO.Path]::DirectorySeparatorChar)
        # We build the destination path by removing the last element and puting the DestinationName
        $newFolder = [System.IO.Path]::Combine([string]::Join("\", $foldersSource, 0, $foldersSource.Count - 1), $DestinationName)
        Move-Item -Path $FileFolderName -Destination $newFolder -Force -ErrorVariable renameStatus
        if ($renameStatus.Count -ne 0)
        {
          $(throw "The renaming failed.")
        }
      }
      elseif (Test-Path -PathType Leaf -Path $FileFolderName)
      {
        # Rename the file
        Rename-Item -Path $FileFolderName -NewName $DestinationName -Force -ErrorVariable renameStatus
        if ($renameStatus.Count -ne 0)
        {
          $(throw "The renaming failed.")
        }
      }
      else
      {
        $(throw "The source file(s) or folder could not be found.")
      }
    }
    # Move a file or a folder
    elseif ($Action -eq "move")
    {
      if ([string]::IsNullOrEmpty($DestinationName))
      {
        $(throw "The destination must be specified.")
      }

      # We determine if the destination already exists
      if ((Test-Path -PathType Container -Path $DestinationName) -or
          (Test-Path -PathType Leaf -Path $DestinationName))
      {
        $(throw "The destination file or folder already exists.")
      }

      # We determine if the source exists
      if ((Test-Path -PathType Container -Path $FileFolderName) -or
          (Test-Path -PathType Leaf -Path $FileFolderName))
      {
        Move-Item -Path $FileFolderName -Destination $DestinationName -Force -ErrorVariable moveStatus
        if ($moveStatus.Count -ne 0)
        {
          $(throw "The moving failed.")
        }
      }
      else
      {
        $(throw "The source file or folder was not found.")
      }
    }
    # Modify the attribute of file(s)
    elseif ($Action -eq "attrib")
    {
      # We get the files selected
      $files = $null
      if (Test-Path -PathType Container -Path $FileFolderName)
      {
        # If the $FileFolderName has either / or \ in the end when the path points
        # to a folder, the object reference for Win32_LogicalFileSecuritySetting will come as null
        # and throws exception
        if ($FileFolderName.EndsWith('/') -or $FileFolderName.EndsWith('\'))
        {
            $FileFolderName = $FileFolderName.Substring(0,$FileFolderName.Length-1)
        }
        $files = Get-Item $FileFolderName -Force
      }
      elseif (Test-Path -PathType Leaf -Path $FileFolderName)
      {
        $files = Get-childitem $FileFolderName -recurse -Force
      }
      if ($files -eq $null)
      {
        $(throw "The source file(s) could not be found.")
      }

      # We affect each attributes specified to the collecton of items that we found
      if ($ReadOnly -eq "+")
      {
        $files | ForEach-Object -process {if (-not ($_.Attributes -band [system.IO.FileAttributes]::ReadOnly)) {$_.Attributes = ($_.Attributes -bxor [system.IO.FileAttributes]::ReadOnly)}}
      }
      elseif ($ReadOnly -eq "-")
      {
        $files | ForEach-Object -process {if ($_.Attributes -band [system.IO.FileAttributes]::ReadOnly) {$_.Attributes = ($_.Attributes -bxor [system.IO.FileAttributes]::ReadOnly)}}
      }
      if ($Archive -eq "+")
      {
        $files | ForEach-Object -process {if (-not ($_.Attributes -band [system.IO.FileAttributes]::Archive)) {$_.Attributes = ($_.Attributes -bxor [system.IO.FileAttributes]::Archive)}}
      }
      elseif ($Archive -eq "-")
      {
        $files | ForEach-Object -process {if ($_.Attributes -band [system.IO.FileAttributes]::Archive) {$_.Attributes = ($_.Attributes -bxor [system.IO.FileAttributes]::Archive)}}
      }
      if ($System -eq "+")
      {
        $files | ForEach-Object -process {if (-not ($_.Attributes -band [system.IO.FileAttributes]::System)) {$_.Attributes = ($_.Attributes -bxor [system.IO.FileAttributes]::System)}}
      }
      elseif ($System -eq "-")
      {
        $files | ForEach-Object -process {if ($_.Attributes -band [system.IO.FileAttributes]::System) {$_.Attributes = ($_.Attributes -bxor [system.IO.FileAttributes]::System)}}
      }
      if ($Hidden -eq "+")
      {
        $files | ForEach-Object -process {if (-not ($_.Attributes -band [system.IO.FileAttributes]::Hidden)) {$_.Attributes = ($_.Attributes -bxor [system.IO.FileAttributes]::Hidden)}}
      }
      elseif ($Hidden -eq "-")
      {
        $files | ForEach-Object -process {if ($_.Attributes -band [system.IO.FileAttributes]::Hidden) {$_.Attributes = ($_.Attributes -bxor [system.IO.FileAttributes]::Hidden)}}
      }
      if (![string]::IsNullOrEmpty($OwnerName))
      {
        if ([string]::IsNullOrEmpty($OwnerDomain) -or $OwnerDomain -eq '""')
        {
          $OwnerDomain = "."
        }

        $SecurityDescriptor = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance()
        $Trustee = ([WMIClass] "Win32_Trustee").CreateInstance()

        $newOwner = (New-Object System.Security.Principal.NTAccount($OwnerDomain, $OwnerName)).Translate([Security.Principal.SecurityIdentifier])
        if ($newOwner -eq $null)
        {
          $(throw "The owner specified is invalid or cannot be accessed.")
        }

        [byte[]] $SIDArray = ,0 * $newOwner.BinaryLength
        $newOwner.GetBinaryForm($SIDArray,0)
        $Trustee.Name = $OwnerName
        $Trustee.SID = $SIDArray
        $SecurityDescriptor.Owner = $Trustee
        
        # Set control flag
        $SecurityDescriptor.ControlFlags="0x8000"

        # Loop through each file / folder
        $files | ForEach-Object -Process {
          
          # Get file or folder object
          $path = "path='" + $_.FullName.Replace("\", "\\") + "'"
          $wPrivilege = GWMI Win32_LogicalFileSecuritySetting -Filter $path
          if ($wPrivilege -eq $null)
          {
              $(throw "The object reference couldn't be find in the logical file security setting.")
          }
          # Enable SeRestorePrivilege (for Windows Vista and Windows Server 2008
          # Not necessary if running in privileged mode)
          
          $wPrivilege.psbase.Scope.Options.EnablePrivileges = $true
          
          # Write  new SecurityDescriptor to file/folder object
          $result = $wPrivilege.SetSecurityDescriptor($SecurityDescriptor)
          if ($result.ReturnValue -ne 0)
          {
              $(throw "The file or folder owner could not be changed: $_")
          }
        }
      }
    }
    else
    {
      $(throw "The action specified is not supported.")
    }
  }
  catch
  {
    Set-ScriptExitCode 9999
    throw $_.Exception
  }
  finally
  {
    # Output outcome of the call.
    if ($exitCode -eq 0)
    {
      "Done.`n"
    }
    else
    {
      Write-Host "Done with errors.`n" -ForegroundColor Red
    }
  }
}

##################################################################################  
# Check for an exit code 
if ($exitCode -eq 0)
{
  try
  {
    # Execute the command.
    Apply-Action -Action $Action -FileFolderName $Filefoldername -DestinationName $DestinationName -ReadOnly $Readonly -Archive $Archive -System $System -Hidden $Hidden -OwnerDomain $OwnerDomain -OwnerName $OwnerName -WorkingDirectory $WorkingDirectory
  }
  catch [System.Exception]
  {
    # Prevent further execution.
    if ($exitCode -eq 0) { $exitCode = 1 }
    #Write-Eventlog -logname 'Application' -source 'Application' -eventID 1000 -EntryType Error -message $_.Exception.Message
    Write-Host $_.Exception.Message "`n" -ForegroundColor Red
   }
}

##################################################################################
# Analyze the result of the execution.

# Determine if we have an error with the process.
if ($exitCode -eq 0)
{
  "The script completed successfully.`n"
}
else
{
  $err = "Exiting with error: " + $exitCode + "`n"
  Write-Host $err -ForegroundColor Red
}

##################################################################################
# Restore any location change.
Pop-Location

##################################################################################
# Complete the process raising the error, if any.
exit $exitCode
# SIG # Begin signature block
# MIIiAAYJKoZIhvcNAQcCoIIh8TCCIe0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC1/wLA5rqS/FbD
# ydkbeHTfts+eAba+/sGD8mAlv/dozaCCC4MwggULMIID86ADAgECAhMzAAAAM1b2
# lB2ajL3lAAAAAAAzMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTAwHhcNMTMwOTI0MTczNTU1WhcNMTQxMjI0MTczNTU1WjCBgzEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UECxMETU9Q
# UjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAs9KaOIfw6Oly8PBcJp2mW2pAcbiYWLBfGneq+Oed
# i8Vc8IrjSTO4bEGak9UTxlyKNykoTjwpF275u22O3FPFEQPJU96Y8PFN7E2x8gh4
# 6ftxxmL9XCqnZGd4YJ+qhW3OPuJq9DLc14DJiKAxmHE69CH3N65QJId20RHix/47
# PaEYkBalXwSZ6JLjG9MJSFwmBVUb3WilzUsPv/XM3lWltHUqcbSZwjsM5NKR2HKK
# +eyHIqxqWb90NUky2K0jSbVnEJgQy9TIljp84OA+7ei+v2Lo4dJ7eAYGodazlE1W
# BQ2vCD7ItSKc/m0QL+tjGxW5kCeRZ/sSHyvcdveB1CphyQIDAQABo4IBejCCAXYw
# HwYDVR0lBBgwFgYIKwYBBQUHAwMGCisGAQQBgjc9BgEwHQYDVR0OBBYEFPBHESyD
# Hm5wg0qUmlqkIi/UPOxLMFEGA1UdEQRKMEikRjBEMQ0wCwYDVQQLEwRNT1BSMTMw
# MQYDVQQFEyozODA3NisxMzVlOTk3ZC0yZmUyLTQ3MWMtYjIxYy0wY2VmNjA1OGU5
# ZjYwHwYDVR0jBBgwFoAU5vxfe7siAFjkck619CF0IzLm76wwVgYDVR0fBE8wTTBL
# oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljQ29kU2lnUENBXzIwMTAtMDctMDYuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggr
# BgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWND
# b2RTaWdQQ0FfMjAxMC0wNy0wNi5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0B
# AQsFAAOCAQEAUCzVYWVAmy0CuJ1srWZf0GzTE7bv6EBw3KVMIUi+aQDV1Cmyip6P
# 0aaVqwn2IU4fZCm9cISyrZvvZtsBgZo427YflDWZwXnJVdOhfnUfXD0Ql0G3/eXq
# nwZrQED6XhbKSWXC6g3R47bWLMO2FxrD+oC81yC5iYGvJFCy+iWW7T7Sp2MMr8nZ
# XUmh7VwqxLmESRL9SG0I1jBJeiw3np61RvhG9K7I3ADQAlAwgs07dOphCztGdya7
# LMU0aPEHo4nShwMWGGISjVayRZ3K3KlQQgWDzrgF4alEgf5eHQObN3ZA01YoN2Ir
# J5IcVCEDiAcMbEMVqFPt6srBJveymDXpPDCCBnAwggRYoAMCAQICCmEMUkwAAAAA
# AAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1
# dGhvcml0eSAyMDEwMB4XDTEwMDcwNjIwNDAxN1oXDTI1MDcwNjIwNTAxN1owfjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWlj
# cm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAOkOZFB5Z7XE4/0JAEyelKz3VmjqRNjPxVhPqaV2fG1FutM5
# krSkHvn5ZYLkF9KP/UScCOhlk84sVYS/fQjjLiuoQSsYt6JLbklMaxUH3tHSwoke
# cZTNtX9LtK8I2MyI1msXlDqTziY/7Ob+NJhX1R1dSfayKi7VhbtZP/iQtCuDdMor
# sztG4/BGScEXZlTJHL0dxFViV3L4Z7klIDTeXaallV6rKIDN1bKe5QO1Y9OyFMjB
# yIomCll/B+z/Du2AEjVMEqa+Ulv1ptrgiwtId9aFR9UQucboqu6Lai0FXGDGtCpb
# nCMcX0XjGhQebzfLGTOAaolNo2pmY3iT1TDPlR8CAwEAAaOCAeMwggHfMBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTm/F97uyIAWORyTrX0IXQjMubvrDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0gBIGVMIGSMIGPBgkrBgEE
# AYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9Q
# S0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcA
# YQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZI
# hvcNAQELBQADggIBABp071dPKXvEFoV4uFDTIvwJnayCl/g0/yosl5US5eS/z7+T
# yOM0qduBuNweAL7SNW+v5X95lXflAtTx69jNTh4bYaLCWiMa8IyoYlFFZwjjPzwe
# k/gwhRfIOUCm1w6zISnlpaFpjCKTzHSY56FHQ/JTrMAPMGl//tIlIG1vYdPfB9XZ
# cgAsaYZ2PVHbpjlIyTdhbQfdUxnLp9Zhwr/ig6sP4GubldZ9KFGwiUpRpJpsyLcf
# ShoOaanX3MF+0Ulwqratu3JHYxf6ptaipobsqBBEm2O2smmJBsdGhnoYP+jFHSHV
# e/kCIy3FQcu/HUzIFu+xnH/8IktJim4V46Z/dlvRU3mRhZ3V0ts9czXzPK5UslJH
# asCqE5XSjhHamWdeMoz7N4XR3HWFnIfGWleFwr/dDY+Mmy3rtO7PJ9O1Xmn6pBYE
# AackZ3PPTU+23gVWl3r36VJN9HcFT4XG2Avxju1CCdENduMjVngiJja+yrGMbqod
# 5IXaRzNij6TJkTNfcR5Ar5hlySLoQiElihwtYNk3iUGJKhYP12E8lGhgUu/WR5mg
# gEDuFYF3PpzgUxgaUB04lZseZjMTJzkXeIc2zk7DX7L1PUdTtuDl2wthPSrXkizO
# N1o+QEIxpB8QCMJWnL8kXVECnWp50hfT2sGUjgd7JXFEqwZq5tTG3yOalnXFMYIV
# 0zCCFc8CAQEwgZUwfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMAITMwAA
# ADNW9pQdmoy95QAAAAAAMzANBglghkgBZQMEAgEFAKCBvjAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkq
# hkiG9w0BCQQxIgQgI5fQh5Q3Ljg/jZ/BI8n0irRKoYLAyu3UFovCjYE1cgswUgYK
# KwYBBAGCNwIBDDFEMEKgKIAmAE0AYQBuAGEAZwBlAFcAaQBuAGQAbwB3AHMASQBP
# AC4AcABzADGhFoAUaHR0cDovL21pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAE
# ggEAWTy5sPlI6iEYXbrqVbsDFDW1I/BZhk1jHX/7O6bJE3l7YjpX3t0XejLnqjCL
# mF/IDLa3/5udLPxGtfe/kBp+HQE2UhMo1sEQqLHoQsfuSTbvbAE96DlodQ1IbCQ4
# Pwh2jRJjas+V5xxGrNrmsRbcxofvVhdCDGtRLqOiDvIDD9FP65pqwy04ouNSbWl2
# wKFTKMZJg13eaO4fBgRUwXnFd+PSBGFw+6ihHeS+UxOGVj56zhxqby6TkmYj+aQq
# IgoAb/A5ruLFpkcV6haAWjlAKi4p5xYa799UNAXQ9YbjrGrhw+RUS8ePXe/u0Xok
# bb8PUsmUOMahZQ+8bJ3/5+D1JqGCE00wghNJBgorBgEEAYI3AwMBMYITOTCCEzUG
# CSqGSIb3DQEHAqCCEyYwghMiAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggE9BgsqhkiG
# 9w0BCRABBKCCASwEggEoMIIBJAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQC
# AQUABCDZTV8n+h10fwBjW8sjnRSqkKn/ln6sj1JPqF1BMjFM7gIGUt6S46QAGBMy
# MDE0MDIyMDE0MjkyMy44MzdaMAcCAQGAAgH0oIG5pIG2MIGzMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMQ0wCwYDVQQLEwRNT1BSMScwJQYDVQQL
# Ex5uQ2lwaGVyIERTRSBFU046QzBGNC0zMDg2LURFRjgxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg7QMIIGcTCCBFmgAwIBAgIKYQmBKgAA
# AAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUg
# QXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0NjU1WjB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77XxoSyxf
# xcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM1024OAiz
# Qt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0ySwcSm
# XdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3WsvYpCTUBR
# 0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnNPOcv
# RLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHiMBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGSMIGPBgkr
# BgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABl
# AGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJ
# KoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+zwXiqf76
# V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKKdsxAQEGb
# 3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/UveYFl2am1
# a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4zu2JfmttX
# QOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHimbdLhnPkd
# /DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlXdqJxqgaK
# D4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/nMQek
# kzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A+xuJKlQ5
# slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdCosnPGUFN
# 4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42neV8HR3jDA
# /czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950iEkS
# MIIE2jCCA8KgAwIBAgITMwAAACiQZ7kEsDxuZgAAAAAAKDANBgkqhkiG9w0BAQsF
# ADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0xMzAzMjcyMDEzMTNa
# Fw0xNDA2MjcyMDEzMTNaMIGzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMQ0wCwYDVQQLEwRNT1BSMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBFU046
# QzBGNC0zMDg2LURFRjgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdpUi/akidSiGc
# kmve4C3c5GP4zLmJxMcbvee10/vtrs8x/vNmsEQD2plnCFq/dQYiEYnQZ1LM+s+S
# N0Xo+vG9M9PMc+O4IaSgFX3LL8QDBdo/lnPTWeWYTQtWhi+dR9HWX52R6ceE2ZVr
# Mky0awBS4EHTPGl0qM7MfWidUlXmcH8UB6KeZ7CGRPMzP3Ndxij4F19SAS1EL9bt
# eAi45TsvwLnDS8O3Oy/TprWcsUhK3TIJVqEbS1rTqiYnDBJDYMVq19pADWCYiUG7
# k3Pdv/7EjFvO+lUnyk1Nmm99EWyxRyOwTHxsfwahdIIfUngY6QYaFlCawzrdgYH3
# mydyIX91AgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQU3JgInXnRBLKLR8Nx0Izns+aw
# U50wHwYDVR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBL
# oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggr
# BgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNU
# aW1TdGFQQ0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAK
# BggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAgiLztz1kfhJL/Cb84OS30MQU
# Tgn+q1aa0VqYpr6MQR6UtDK+hLS3RXbj72AYJIeoz+m00VQpvMrkyxJ7wPHUDp8x
# MxsRP3o73d0CqhjKyjz6luNsu6+7yYQ+x9gMhctyCwEbpPUxERAMRaVaSJl+2r5F
# hte6TeSB/9NYCnZlBlkv9sJCzwTJqxv6YZ3185hJcLFJ0GTEIejuYBdTfusC2miV
# i/UKPAHbo7WYFFF0nlPp2nKYZqBfKc+Prx+CnNPr5vFMG1T46DLcwRXDrCpudAUW
# g+NEmJ/L7+gweX+vUqU6H99lx43+J9hHGZIItIs0jmknNxoC9pGzlSL/CEgq/qGC
# A3kwggJhAgEBMIHjoYG5pIG2MIGzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMQ0wCwYDVQQLEwRNT1BSMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBF
# U046QzBGNC0zMDg2LURFRjgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiJQoBATAJBgUrDgMCGgUAAxUA8120HsdfO2ZOZQ7emART9hWnH0Sg
# gcIwgb+kgbwwgbkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# DTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgTlRTIEVTTjpCMDI3LUM2
# RjgtMUQ4ODErMCkGA1UEAxMiTWljcm9zb2Z0IFRpbWUgU291cmNlIE1hc3RlciBD
# bG9jazANBgkqhkiG9w0BAQUFAAIFANavvjowIhgPMjAxNDAyMTkyMzM1MjJaGA8y
# MDE0MDIyMDIzMzUyMlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA1q++OgIBADAK
# AgEAAgIDvAIB/zAHAgEAAgIWzjAKAgUA1rEPugIBADA2BgorBgEEAYRZCgQCMSgw
# JjAMBgorBgEEAYRZCgMBoAowCAIBAAIDFuNgoQowCAIBAAIDB6EgMA0GCSqGSIb3
# DQEBBQUAA4IBAQA73pHZWXNVQyCYGDHA31uxlnPv7QF2yUYSNR7NQ9tKLi411mJE
# 7mNXwlLRfq5SksTb0ZG3HiEezrIZwdZpCpouZItrw5mxIyDWKKBNKTe9jEnA5RhG
# 2in9SdyXASdadkgvZt8M+no0wVmudCJovxVn2EsD7pmhaHujHw5ecksW2L4Tokxr
# uHC4Snwhc4eZSedlqDA1wg/e/ttIGy3TS8yGEFyqhm2DI4/NVr6VuTB3fWkvOTmg
# Esw6nCw8cSmOUNK1LFYbFdyTsgMPrRdPSQA9+YpMYYqaMegaeI7cf8/3zu3U26Im
# aT/L9NmVOlN1aw9JyC69+sLJjeedeOsw6lQZMYIC9TCCAvECAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAAokGe5BLA8bmYAAAAAACgwDQYJ
# YIZIAWUDBAIBBQCgggEyMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgmpKU4gaLbbPjp19iwtftUjLGgaW9oRdfNVRjYiIwisgwgeIG
# CyqGSIb3DQEJEAIMMYHSMIHPMIHMMIGxBBTzXbQex187Zk5lDt6YBFP2FacfRDCB
# mDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAAKJBnuQSw
# PG5mAAAAAAAoMBYEFLNq5lg1khn+JEwZFapRbb1IAn/AMA0GCSqGSIb3DQEBCwUA
# BIIBACIkQR204pMOkzao6aMicszzjPpdiAYJ2vn4tTayS8qiGnn+yQBxxF4H3Jsz
# V1NGz9sHQ27ArJkaQD/gdCa1fCV59o2D+rJLxrf7fcUXGDrOTyoz7YKiA1S+ByJc
# PP0i1rNKP+2nRFHHE5Rk2cet0GO1mtQnwxSiB2hKe77bXlnaIKIGsnw1ju8b8Vtq
# zb2XwTqntZEpyzX2SjVs0ZfiSBkAGQsQrA19sI0kM3h1aObqe72LeNvJdaNxp8s7
# C+u0cYWFSRtrX9KnAiJEjsjIKb43oR9j9U9/a5qCZpt5l3U4k2yEXP2hXycPbTpK
# 6CzfxE5IjVqENqVKwyVOK+40uNw=
# SIG # End signature block
