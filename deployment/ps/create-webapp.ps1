## Intro: Simple powershell script to install (or replace) a local web application and app pool
## Usage: create-webapp.ps1 [WebSiteName] [WebAppName] [AppPoolName] [PhysicalPath] [IsPreloadEnabled]
## Note : These scripts require local admin priviliges!

# Load IIS tools
Import-Module WebAdministration
sleep 2 #see http://stackoverflow.com/questions/14862854/powershell-command-get-childitem-iis-sites-causes-an-error

# Get SiteName and AppPool from script args
$siteName    = $args[0]  # "default web site"
$appName     = $args[1]  # "appName"
$appPoolName = $args[2]  # "DefaultAppPool"
$path        = $args[3]  # "c:\sites\test"
$preload     = $args[4]  # "true|false"

try { 

    if($siteName -eq $null)    { throw "Empty WebSiteName, Argument one is missing" }
    if($appName -eq $null)     { throw "Empty WebAppName, Argument two is missing" }
    if($appPoolName -eq $null) { throw "Empty AppPoolName, Argument three is missing" }
    if($path -eq $null)        { throw "Empty PhysicalPath, Argument four is missing" }
}
catch [Exception] {

    Write-Host $_.Exception.GetType().FullName; 
    Write-Host $_.Exception.Message; 

    # return a non-zero exit code, because an error occurred
    exit 100
}

try {

    $backupName = "$(Get-date -format "yyyyMMdd-HHmmss")-$siteName-$appName"
    "Backing up IIS config to backup named $backupName"
    $backup = Backup-WebConfiguration $backupName
        
    # delete the webapp & app pool if needed
    if (Test-Path "IIS:\Sites\$siteName\$appName") {
        "Removing existing application $siteName\$appName"
        Remove-WebApplication -Name $appName -Site $siteName
    }

    "Create a web application $siteName\$appName from directory $path"
    $webapp = New-WebApplication -Name $appName -ApplicationPool $appPoolName -PhysicalPath $path -Site $siteName

    "Web Application created and started sucessfully"

} 

catch [Exception] {

    Write-Host $_.Exception.GetType().FullName; 
    Write-Host $_.Exception.Message; 

    "Error detected, running command 'Restore-WebConfiguration $backupName' to restore the web server to its initial state. Please wait..."
    sleep 5 #allow backup to unlock files
    
    Restore-WebConfiguration $backupName
    "IIS Restore complete. Throwing original error."

    # return a non-zero exit code, because an error occurred
    exit 100
}

