# OpenSSH-Win-Config
A Powershell script to download and config OpenSSH for Windows operating systems.

Uses the latest release of [this](https://github.com/PowerShell/Win32-OpenSSH/) GitHub repo for downloading the OpenSSH binaries.

## Example Usage:

Install OpenSSH allowing only public key authentication and installing a key:

`.\OpenSSH-Win-Config.ps1 -Install -Download -PublicKeyOnly -KeyPath "C:\temp\key.pub"`

Only Download the binaries, not installing:

`.\OpenSSH-Win-Config.ps1 -DownloadOnly`

If you are on a computer which has no Internet connection, you need to pass the path to the files to the -binarieDirPath flag, and the command should be run in the same way, but without `-Download` or `-DownloadOnly`.

`.\OpenSSH-Win-Config.ps1 -Install -binarieDirPath "C:\temp\OpenSSH-Win64" -PublicKeyOnly -KeyPath "C:\temp\key.pub"`

Adds a new key to the administrators_authorized_keys file

`.\OpenSSH-Win-Config.ps1 -Config -AddKey -KeyPath "C:\temp\key.pub"`

Fixes the file permissions needed by OpenSSH

`.\OpenSSH-Win-Config.ps1 -Config -FilePermissions`

Fixes the file permissions on the directory where OpenSSH is installed

`.\OpenSSH-Win-Config.ps1 -Config -InstallDirPermissions -InstallDirPath "C:\OpenSSH-Win64"`

## Possible flags:

   **-Install:** Needed if you pretend to install OpenSSH on Windows. Default: `$false` (Boolean)

   **-Config:** Configuration related, demands OpenSSH installed. Default: `$false` (Boolean)

   **-Uninstall:** Uninstalls OpenSSH from the machine. Default: `$false` (Boolean)

   **-TempPath:** Path used for temporary files like downloading and extracting from github. Default: `C:\temp` (String)

   **-BinarieDirPath:** The path to thebinaries folder for the OpenSSH software. Default: `$TempPath\OpenSSH-Win$($Architecture)` (String)

   **-InstallDirPath:** The path where OpenSSH will be installed. Default: `C:\OpenSSH-Win$($Architecture)` (String)

   **-FilePermissions** Used with the -Config flag, used when you want to correct the permissions of files used by the OpenSSH software. Default: `$false` (Boolean)

   **-InstallDirPermissions:** Used with the -Config flag, used when you want to correct the permissions of the directory where OpenSSH was installed. Default: `$false` (Boolean)

   **-AddPublicKey:** Used with the -Config flag, used when you want to add another key to the administrators_authorized_keys file. Needs a KeyPath defined. Default: `$false` (Boolean)

   **-sslVerify:** Checks for valid certificate. Used with the -Download flag. Default: `$false` (Boolean)

   **-Verbose:** Adds verbosity level to script output. Default: `$false` (Boolean)

   **-Download:** Defines if will try to download the binaries from GitHub or install directly from machine. Default: `$false` (Boolean)

   **-Shell:** Defines if the default shell after ssh into the machine will be cmd or powershell. Default: `powershell` (String)

   **-Architecture:** Defines if the binarie architecture will be 64 or 32 bits. Default: `64` (Int)
   
   **-DownloadOnly:** Only downloads the binaries to `C:\temp\`, not installing. Default: `$false` (Boolean)
   
   **-PublicKeyOnly:** Defines if only public key authentication will be enabled. Default: `$false` (Boolean)
   
   **-PublicKey:** Defines if public key authentication will be allowed. Default: `$false` (Boolean)
   
   **-KeyPath:** Defines the path to the key file for using with public key authentication. Default: `$null` (String)

   **-ServicePort:** Defines the port on which SSH will listen. Default: `22` (Int)

   **-SharedFolder:** Defines if the folder used will be shared or can be moved (instead of copied). Default: `$false` (Boolean)



## Issues

If you find any problems, please open an issue at [the issues page](https://github.com/aJesus37/OpenSSH-Config/issues)