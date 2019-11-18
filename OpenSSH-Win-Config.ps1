param(
    [string]$Shell = "powershell", [switch]$Download = $false, [switch]$Verbose = $false, [string]$Architecture = 64, [switch]$DownloadOnly = $false,[switch]$PublicKeyOnly=$false,[string]$KeyPath="",[switch]$PublicKey=$false,[switch]$sslVerify=$false,$tempPath="C:\temp",[string]$binarieDirPath="$tempPath\OpenSSH-Win$($Architecture)",[string]$installDirPath="C:\OpenSSH-Win$($architecture)"
)

if ($Architecture -ne "64" -And $Architecture -ne "32" -And $Architecture -ne 64 -And $Architecture -ne 32) {
    Write-Output "Only 32 or 64 are allowed as values for -architecture. Exitting..."
    exit 1
}

$KeyPath=Resolve-Path -Path "$KeyPath";
$tempPath=Resolve-Path -Path "$tempPath";
$binarieDirPath=Resolve-Path -Path "$binarieDirPath";
$installDirPath=Resolve-Path -Path "$installDirPath";

if ($Verbose){
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
    "
}



if ($Download -Or $DownloadOnly) {
    if (-Not (Test-Path "$tempPath")) {
        New-Item -ItemType Directory -Path "$tempPath"
    }
    if (-Not $sslVerify){
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
        Invoke-WebRequest -Uri "https://gitreleases.dev/gh/PowerShell/Win32-OpenSSH/latest/OpenSSH-Win$($Architecture).zip" -OutFile "$tempPath\OpenSSH-Win$($Architecture).zip"
        if ($Verbose) { Write-Output "[+] Extracting file..." }
        Expand-Archive -LiteralPath "$tempPath\OpenSSH-Win$($Architecture).zip" -DestinationPath "$tempPath\OpenSSH-Win"
        if ($Verbose) { Write-Output "[+] Moving folder to $tempPath\" }
        Move-Item -LiteralPath "$tempPath\OpenSSH-Win\OpenSSH-Win$($Architecture)" -Destination "$tempPath\OpenSSH-Win$($Architecture)"
        Remove-Item -LiteralPath "$tempPath\OpenSSH-Win" -Force
    }
    catch {
        Write-Output "Erros happened while downloading or extracting the files. Please read below:`n";
        Write-Output "[Error] $_.Exception.Message"
    }
    if ($DownloadOnly) {
        exit 0;
    }
}

if ($Verbose){Write-Output "[+] Moving Folder to $installDirPath"}
Move-Item -Path "$binarieDirPath" -Destination "$installDirPath"

$UsersPermissions = New-Object System.Security.AccessControl.FileSystemAccessRule "Users","ReadAndExecute, Synchronize", "ContainerInherit, ObjectInherit", "InheritOnly", "Allow"
$Acl = Get-Acl C:\OpenSSH-Win64
$Acl.SetAccessRule($UsersPermissions)
Set-Acl $installDirPath $Acl

if ($Verbose){Write-Output "[+] Installing sshd as service"}
& "$installDirPath\install-sshd.ps1"
& "$installDirPath\install-sshd.ps1"

if ($Verbose){Write-Output "[+] Adding firewall rule to Windows firewall"}
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

if ($Verbose){Write-Output "[+] Changing startup and status of services"}
Set-Service sshd -StartupType Automatic
Set-Service ssh-agent -StartupType Automatic
Start-Service sshd
Start-Service ssh-agent


if ($shell -eq "powershell") {
    if ($Verbose){Write-Output "Changing Default shell"}
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShellCommandOption -Value "/c" -PropertyType String -Force
}

if ($Verbose){Write-Output "Stopping services"}
Stop-Service sshd
Stop-Service ssh-agent

if ($Verbose){Write-Output "Creating administrators_authorized_keys file"}
New-Item -ItemType File -Path C:\ProgramData\ssh\administrators_authorized_keys

if ($Verbose){Write-Output "Changing path"}
$oldSysPath = (Get-Itemproperty -path 'hklm:\system\currentcontrolset\control\session manager\environment' -Name Path).Path
$newSysPath = $oldSysPath + ";C:\OpenSSH-Win64\"
Set-ItemProperty -path 'hklm:\system\currentcontrolset\control\session manager\environment' -Name Path -Value $newSysPath 


if ($Verbose){Write-Output "Fixing permissions"}
& "C:\OpenSSH-Win64\FixHostFilePermissions.ps1" -Confirm:$false
try { & "C:\OpenSSH-Win64\FixUserFilePermissions.ps1" -Confirm:$fals } catch { } # Not every user will use ssh as non-admin

if ($Verbose){Write-Output "Importing module"}
Import-Module "C:\OpenSSH-Win64\OpenSSHUtils.psm1"

if ($Verbose){Write-Output "Setting content to administrators_authorized_keys file"}
Get-Content "$KeyPath" | Out-File -Encoding utf8 "C:\ProgramData\ssh\administrators_authorized_keys" -Append

if ($Verbose){Write-Output "Changing administrators_authorized_keys file"}
Repair-FilePermission -FilePath "C:\ProgramData\ssh\administrators_authorized_keys" -Confirm:$false

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

if ($Verbose){Write-Output "Starting services"}
Start-Service sshd  
Start-Service ssh-agent
