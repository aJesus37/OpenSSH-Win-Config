param(
    [switch]$install = $false, [switch]$config = $false, [switch]$uninstall = $false, [string]$Shell = "powershell", [switch]$Download = $false, [switch]$Verbose = $false, [string]$Architecture = 64, [switch]$DownloadOnly = $false, [switch]$PublicKeyOnly = $false, [string]$KeyPath = "", [switch]$PublicKey = $false, [switch]$sslVerify = $false, $tempPath = "C:\temp", [string]$binarieDirPath = "$tempPath\OpenSSH-Win$($Architecture)", [string]$installDirPath = "C:\OpenSSH-Win$($architecture)", [switch]$FilePermissions = $false, [switch]$installDirPermissions = $false, [switch]$addPublicKey = $false
)

if ($Architecture -ne "64" -And $Architecture -ne "32" -And $Architecture -ne 64 -And $Architecture -ne 32) {
    # Check whether the architecture is 32 or 64 bits. Closes if different.
    Write-Output "Only 32 or 64 are allowed as values for -architecture. Exitting..."
    exit 1
}
# Resolve the paths into absolute paths
$tempVar = Resolve-Path -Path "$KeyPath" -ErrorAction Ignore
if ($tempVar) { 
    $KeyPath = $tempVar; Clear-Variable tempVar
}

$tempVar = Resolve-Path -Path "$tempPath" -ErrorAction Ignore
if ($tempVar) {
    $tempPath = $tempVar; Clear-Variable tempVar
}

$tempVar = Resolve-Path -Path "$binarieDirPath" -ErrorAction Ignore
if ($tempVar) {
    $binarieDirPath = $tempVar; Clear-Variable tempVar
}
#Show variable contents if verbose
if ($Verbose) {
    Write-Output "
    Shell: $Shell
    Download: $Download
    Verbose: $Verbose
    Architecture: $Architecture
    DownloadOnly: $DownloadOnly
    PublicKeyOnly: $PublicKeyOnly
    KeyPath: $KeyPath
    PublicKey: $PublicKey
    sslVerify: $sslVerify
    tempPath: $tempPath
    binarieDirPath: $binarieDirPath
    installDirPath: $installDirPath
    "
}

function Get-Download {
    # Downloads the binaries for the OpenSSH
    if ($Download -Or $DownloadOnly) {
        if (-Not $sslVerify) {
            ######ignore invalid SSL Certs - Do Not Change
            try {
                add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@ 
            }
            catch { }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy 
            #######################################################################################
        }
        try {
            if ($Verbose) { Write-Output "[+] Downloading latest release of OpenSSH-Win$($Architecture)" }
            Invoke-WebRequest -Uri "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win$($Architecture).zip" -OutFile "$tempPath\OpenSSH-Win$($Architecture).zip"
            if ($Verbose) { Write-Output "[+] Extracting file..." }
            Expand-Archive -LiteralPath "$tempPath\OpenSSH-Win$($Architecture).zip" -DestinationPath "$tempPath\OpenSSH-Win"
            if ($Verbose) { Write-Output "[+] Moving folder to $tempPath\" }
            Move-Item -LiteralPath "$tempPath\OpenSSH-Win\OpenSSH-Win$($Architecture)" -Destination "$tempPath\OpenSSH-Win$($Architecture)"
            Remove-Item -LiteralPath "$tempPath\OpenSSH-Win" -Force
        }
        catch {
            Write-Output "Erros happened while downloading or extracting the files. Please read below:`n";
            Write-Output "[Error] $_.Exception.Message"
            exit 1;
        }
        if ($DownloadOnly) {
            exit 0;
        }
    }
}

function Set-InstallDirPermissions {
    # Define correct User permissions for the installer directory
    $UsersPermissions = New-Object System.Security.AccessControl.FileSystemAccessRule "Users", "ReadAndExecute, Synchronize", "ContainerInherit, ObjectInherit", "InheritOnly", "Allow"
    $Acl = Get-Acl $installDirPath
    $Acl.SetAccessRule($UsersPermissions)
    Set-Acl $installDirPath $Acl
}

function Set-FirewallPermission {
    # Create windows firewall rule enabling traffic on port 22
    if ($Verbose) { Write-Output "[+] Adding firewall rule to Windows firewall" }
    try { New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue }
    catch [Microsoft.Management.Infrastructure.CimException] {
        if ($Verbose) { Write-Output "[?] Regra já criada, continuando ..." }
        Write-Host $_.Exception.ToString()
    }
    catch {
        if ($Verbose) { Write-Output "Trying old windows Syntax to firewall rule" }
        Write-Host $_.Exception.ToString()
        try {
            netsh advfirewall firewall add rule name=sshd dir=in action=allow protocol=TCP localport=22 -ErrorAction SilentlyContinue
        }
        catch { 
            if ($Verbose) { Write-Output "Could not create windows firewall rule. Exitting..." }
            Write-Host $_.Exception.ToString()
            exit 1;
        } 
    }
}

function Set-FilePermissions {
    #Fix file permissions. Needed by OpenSSH Windows port to work
    if ($Verbose) { Write-Output "Fixing permissions" }
    & "C:\OpenSSH-Win64\FixHostFilePermissions.ps1" -Confirm:$false
    try { & "C:\OpenSSH-Win64\FixUserFilePermissions.ps1" -Confirm:$fals } catch { } # Not every user will use ssh as non-admin

    if ($Verbose) { Write-Output "Importing module" }
    Import-Module "C:\OpenSSH-Win64\OpenSSHUtils.psm1"
    
    if ($Verbose) { Write-Output "Changing administrators_authorized_keys file permissions" }
    Repair-FilePermission -FilePath "C:\ProgramData\ssh\administrators_authorized_keys" -Confirm:$false
}

function Set-PublicKeyConfig {
    # Defines if public key will be enabled or mandatory
    if ($PublicKeyOnly) {
        if ($Verbose) { Write-Output "[+] Changing sshd_config for using keys only" }
        $key_config = @"
        
        PubkeyAuthentication  yes
        PasswordAuthentication no
        ChallengeResponseAuthentication no

"@
        $ssh_config = $(Get-Content "C:\ProgramData\ssh\sshd_config" -Encoding utf8)
        Move-Item -Path "C:\ProgramData\ssh\sshd_config" -Destination "C:\ProgramData\ssh\sshd_config.old"
        $key_config, $ssh_config | Out-File -Encoding utf8 "C:\ProgramData\ssh\sshd_config"
    }
    elseif ($PublicKey) {
        $key_config = @"
        PubkeyAuthentication  yes

"@
        $ssh_config = $(Get-Content "C:\ProgramData\ssh\sshd_config" -Encoding utf8)
        Move-Item -Path "C:\ProgramData\ssh\sshd_config" -Destination "C:\ProgramData\ssh\sshd_config.old"
    }
}

function Add-PublicKey {
    # Add a new public key to the administrators keys file
    if ($KeyPath -eq "") {
        Write-Output "[!] Error, you need to give a path to a key with the -KeyPath flag. Exitting..."
        exit 1;
    }
    if ($Verbose) { Write-Output "Setting content to administrators_authorized_keys file" }
    Get-Content "$KeyPath" | Out-File -Encoding utf8 "C:\ProgramData\ssh\administrators_authorized_keys" -Append
}

function Main {
    # Main function

    if ( -Not (Test-Path $tempPath)) {
        # Check if the temporary folder given exists, if not creates it
        if ($Verbose) { Write-Output "Creating temporary file path" }
        New-Item -ItemType Directory -Path $tempPath 2>&1> $null
    }
    Get-Download # Downloads binarie for OpenSSH

    if ($install) {
        # Installation begins here
        if ($Verbose) { Write-Output "[+] Moving Folder to $installDirPath" }
        if ($binarieDirPath -ne $installDirPath) {
            Move-Item -Path "$binarieDirPath" -Destination "$installDirPath"
        }
        
        Set-installDirPermissions # Set Installation directory file permissions to group Users
        
        if ($Verbose) { Write-Output "[+] Installing sshd as service" }
        & "$installDirPath\install-sshd.ps1" # Install sshd as a service. Builtin with the binarie
        
        Set-firewallPermission # Create firewall rule
        
        if ($Verbose) { Write-Output "[+] Changing startup and status of services" } # Change startup type and start services to create the C:\ProgramData\ssh\ folder and files
        Set-Service sshd -StartupType Automatic
        Set-Service ssh-agent -StartupType Automatic
        Start-Service sshd
        Start-Service ssh-agent
        
        
        if ($shell -eq "powershell") {
            # Defines powershell as default shell
            if ($Verbose) { Write-Output "Changing Default shell" }
            New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShellCommandOption -Value "/c" -PropertyType String -Force
        }
        
        if ($Verbose) { Write-Output "Stopping services" }
        Stop-Service sshd
        Stop-Service ssh-agent
    
        if ( -Not (Test-Path C:\ProgramData\ssh\administrators_authorized_keys)) {
            # Check if file already exists, if not creates it
            if ($Verbose) { Write-Output "Creating administrators_authorized_keys file" }
            New-Item -ItemType File -Path C:\ProgramData\ssh\administrators_authorized_keys
        }
        
        if ($Verbose) { Write-Output "Changing path" } # Changing environment variable PATH to add the path to the binaries
        $oldPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        $newPath = $oldPath + ";$installDirPath"
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath

        Set-FilePermissions # Set files need by OpenSSH permissions
    
        if ($KeyPath -ne "") {
            # Add public key if a path was given
            Add-PublicKey
        }
        
        Set-PublicKeyConfig # Define public key permissions
        
        if ($Verbose) { Write-Output "Starting services" }
        Start-Service sshd  
        Start-Service ssh-agent
    }

    if ($config) {
        # Configuration use case
        if ($FilePermissions) {
            Set-FilePermissions # Set files need by OpenSSH permissions
        }

        if ($installDirPermissions) {
            Set-InstallDirPermissions # Set Installation directory file permissions to group Users
        }

        if ($addPublicKey) {
            Add-PublicKey # Add public key
        }
    }

    if ($uninstall) {
        # Uninstall use case
        Write-Output "[!] Uninstalling OpenSSH. Make sure the correct install path is being used. Actual: $installDirPath"
        if ((Read-Host -Prompt "Is this directory right? [y/N]") -imatch "y|Y|YES|yes|Yes") {    
            if ($Verbose) { Write-Output "[+] Stopping services" }
            Stop-Service sshd
            Stop-Service ssh-agent

            try {
                if ($Verbose) { Write-Output "[+] Uninstalling sshd" }
                & "$installDirPath\uninstall-sshd.ps1" # Remove sshd as service using builtin binaries
            }
            catch {
                if ($Verbose) { Write-Output "[!] Could not uninstall sshd with the $installDirPath\uninstall-sshd.ps1 script:" }
                Write-Host $_.Exception.ToString()
            }

            try {
                # Remove programdata dir
                if ($Verbose) { Write-Output "[+] Removing folder C:\ProgramData\ssh\" }
                Remove-Item -Force -Recurse -Path "C:\ProgramData\ssh\"
            }
            catch {
                if ($Verbose) { Write-Output "[!] Could not remove folder C:\ProgramData\ssh\, is it being used?" }
                Write-Host $_.Exception.ToString()
            }

            try {
                # Remove installation dir
                if ($Verbose) { Write-Output "[+] Removing folder $installDirPath" }
                Remove-Item -Force -Recurse -Path "$installDirPath"
            }
            catch {
                if ($Verbose) { Write-Output "[!] Could not remove folder $installDirPath, is it being used?" }
                Write-Host $_.Exception.ToString()
            }
            if ($Verbose) { Write-Output "[+] Uninstall Succeded. Exitting..." }
        }
        else {
            Write-Host "Exitting ..."
            exit 0;
        }
    }
}

Main # Run main function