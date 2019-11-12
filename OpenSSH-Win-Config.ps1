param(
    [String]$Shell = "powershell", [switch]$Download = $false, [switch]$Verbose = $false, [string]$Architecture = 64, [switch]$DownloadOnly = $false,[switch]$PublicKeyOnly=$false,[string]$KeyPath="",[switch]$PublicKey=$false,[switch]$sslVerify=$false,[string]$binarieDirPath="C:\temp\OpenSSH-Win$($Architecture)",[string]$installDirPath="C:\OpenSSH-Win$($Architecture)\",[string]$tempPath="C:\temp\"
)

if ($Architecture -ne "64" -And $Architecture -ne "32" -And $Architecture -ne 64 -And $Architecture -ne 32) {
    Write-Output "Only 32 or 64 are allowed as values for -architecture. Exitting..."
    exit 1
}

function Remove-Install{
    Stop-Service sshd
    Stop-Service ssh-agent
    Remove-Item -Recurse -Force C:\ProgramData\ssh\
    Remove-Item -Recurse -Force $installDirPath
}

if (-Not (Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp"
}

if ($Download -Or $DownloadOnly) {
if( -Not $sslVerify){
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
        try {
            Invoke-WebRequest -Uri "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win$($Architecture).zip" -OutFile "$tempPath\OpenSSH-Win$($Architecture).zip"
        } catch {
            Write-Output "Error happened in the binarie download. Exitting...";
            exit 1;
        }
        if ($Verbose) { Write-Output "[+] Extracting file..." }
        Expand-Archive -LiteralPath "$tempPath\OpenSSH-Win$($Architecture).zip" -DestinationPath "$tempPath\OpenSSH-Win"
        if ($Verbose) { Write-Output "[+] Moving folder to C:\temp\" }
        Move-Item -LiteralPath "$tempPath\OpenSSH-Win\OpenSSH-Win$($Architecture)" -Destination "$binarieDirPath"
        Remove-Item -LiteralPath "$tempPath\OpenSSH-Win" -Force
    }
    catch {
        Write-Output "Erros happened while downloading or extracting the files. Please read below:`n";
        Write-Output "[Error] $($_.Exception.Message)"
    }
    if ($DownloadOnly) {
        exit 0;
    }
}

Write-Output "[+] Moving Folder to $installDirPath"
try { Move-Item -Path "$binarieDirPath" -Destination "$installDirPath" }
catch {
    Write-Output "Couldn't move $binarieDirPath to $installDirPath.`nError:"
    Write-Output "[Error] $($_.Exception.Message)"
    exit 1;
}

Write-Output "[+] Installing sshd as service"
& "$installDirPath\install-sshd.ps1"

Write-Output "[+] Adding firewall rule to Windows firewall"
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
    catch { }
}

Write-Output "[+] Changing startup and status of services"
try {
    Set-Service sshd -StartupType Automatic
    Set-Service ssh-agent -StartupType Automatic
    Start-Service sshd
    Start-Service ssh-agent
} catch {
    Write-Output "Error while setting sshd and ssh-agent to startup automatic or to start the services."
    exit 1;
}



if ($shell -eq "powershell") {
    Write-Output "Changing Default shell"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShellCommandOption -Value "/c" -PropertyType String -Force    
    } catch {
        Write-Output "Couldn't change default shell to powershell.`nError:"
        Write-Output "[Error] $($_.Exception.Message)"
    }
    }

    try {
        Write-Output "Stopping services"
        Stop-Service sshd
        Stop-Service ssh-agent
    } catch {
        Write-Output "Couldn't stop the services`nError:"
        Write-Output "[Error] $($_.Exception.Message)"
    }


    try {
        Write-Output "Creating administrators_authorized_keys file"
        New-Item -ItemType File -Path C:\ProgramData\ssh\administrators_authorized_keys        
    } catch {
        Write-Output "Couldn't create the administrators keys file`nError:"
        Write-Output "[Error] $($_.Exception.Message)"
        exit 1;
    }

    try {
        Write-Output "Changing path to add binaries"
        $oldSysPath = (Get-Itemproperty -path 'hklm:\system\currentcontrolset\control\session manager\environment' -Name Path).Path
        $newSysPath = $oldSysPath + ";$installDirPath\"
        Set-ItemProperty -path 'hklm:\system\currentcontrolset\control\session manager\environment' -Name Path -Value $newSysPath 
    } catch {
        Write-Output "Couldn't change system's path`nError:"
        Write-Output "[Error] $($_.Exception.Message)"
    }



    try{
        Write-Output "Fixing permissions"
        & "$installDirPath\FixHostFilePermissions.ps1" -Confirm:$false
       # & "$installDirPath\FixUserFilePermissions.ps1" -Confirm:$false # Later implement user mode (non-admin) for remotely connecting.
    } catch {
        Write-Output "Couldn't fix files permissions. Without this step the install cannot continue`nError:"
        Write-Output "[Error] $($_.Exception.Message)"
        exit 1;
    }

try {
    Write-Output "Importing module"
    Import-Module "$installDirPath\OpenSSHUtils.psm1"
    
    Write-Output "Setting content to administrators_authorized_keys file"
    Get-Content "$KeyPath" | Out-File -Encoding utf8 "C:\ProgramData\ssh\administrators_authorized_keys" -Append
    
    Write-Output "Changing administrators_authorized_keys file"
    Repair-FilePermission -FilePath "C:\ProgramData\ssh\administrators_authorized_keys" -Confirm:$false
} catch {
    Write-Output "Couldn't add keys to the administrators key file`nError:"
    Write-Output "[Error] $($_.Exception.Message)"
}


if($PublicKeyOnly){
    if($Verbose){Write-Output "[+] Changing sshd_config for using keys only"}
    $key_config = $(Write-Output "`nPubkeyAuthentication  yes`nPasswordAuthentication no`nChallengeResponseAuthentication no`nUsePAM  no`n")

    $ssh_config = $(Get-Content "C:\ProgramData\ssh\sshd_config" -Encoding utf8)
    Move-Item -Path "C:\ProgramData\ssh\sshd_config" -Destination "C:\ProgramData\ssh\sshd_config.old"
    $key_config, $ssh_config | Out-File -Encoding utf8 "C:\ProgramData\ssh\sshd_config"
} elseif ($PublicKey) {
    $key_config = $(Write-Output "`nPubkeyAuthentication  yes`n")
    $ssh_config = $(Get-Content "C:\ProgramData\ssh\sshd_config" -Encoding utf8)
    Move-Item -Path "C:\ProgramData\ssh\sshd_config" -Destination "C:\ProgramData\ssh\sshd_config.old"
}

try {
    Write-Output "Starting services"
    Start-Service sshd  
    Start-Service ssh-agent
} catch {
    Write-Output "Couldn't start services, probably some configuration is wrong in the ssh_config file`nError:"
    Write-Output "[Error] $($_.Exception.Message)"
}

