## Intro: Simple powershell script to install (or replace) a local website and app pool
## Usage: CreateSite.ps1 [WebsiteName] [AppPoolName] [Port] [Path] ([domain\user] [password])
## Note : These scripts require local admin priviliges!

# Load IIS tools
Import-Module WebAdministration
sleep 2 #see http://stackoverflow.com/questions/14862854/powershell-command-get-childitem-iis-sites-causes-an-error

# Get SiteName and AppPool from script args
$siteName    = $args[0]  # "default web site"
$virtualFolder = $args[1]  # "VirtualFolder"
$physicalFolder         = $args[2]  # "PhysicalFlder"

try{
    if($siteName -eq $null)    { throw "Empty site name, Argument one is missing" }
    if($virtualFolder -eq $null) { throw "Empty virtualFolder name, Argument two is missing" }
    if($physicalFolder -eq $null)        { throw "Empty physicalFolder, Argument three is missing" }



    $commitpath = 'IIS:\Sites\' + $siteName + '\' + $virtualFolder;

    # delete the virtual directory if needed
    if (Test-Path $commitpath) {
        "Virtual Directory already exists.  Nothing to do here."
    }
    else
    {
        "Create a virtual directory $virtualFolder at path $commitpath from directory $physicalFolder"
        New-Item $commitpath -PhysicalPath $physicalFolder -Type VirtualDirectory  -ea stop
        
        "VirtualDirectory created sucessfully"
    }

}
catch [Exception] {

    Write-Host $_.Exception.GetType().FullName; 
    Write-Host $_.Exception.Message; 

    # return a non-zero exit code, because an error occurred
    exit 100
}


