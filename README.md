# OpenSSH-Win-Config
A Powershell script to download and config OpenSSH for Windows operating systems.

Uses the latest release of [this](https://github.com/PowerShell/Win32-OpenSSH/) GitHub repo for downloading the OpenSSH binaries.

## Example Usage:

Install OpenSSH allowing only public key authentication and installing a key:

`.\OpenSSH-Win-Config.ps1 -Download -PublicKeyOnly -KeyPath "C:\temp\key.pub"`

Only Download the binaries, not installing:

`.\OpenSSH-Win-Config.ps1 -DownloadOnly`

If you are on a computer which has no Internet connection, the files at Win32-OpenSSH folder should be moved to `C:\temp\OpenSSH-Win[64|32]` and the command should be run in the same way, but without `-Download` or `-DownloadOnly`.

`.\OpenSSH-Win-Config.ps1 -PublicKeyOnly -KeyPath "C:\temp\key.pub"`

## Possible flags:

   **-Verbose:** Adds verbosity level to script output. Default: `$false`

   **-Download:** Defines if will try to download the binaries from GitHub or install directly from machine. Default: `$false`

   **-Shell:** Defines if the default shell after ssh into the machine will be cmd or powershell. Default: `powershell`

   **-Architecture:** Defines if the binarie architecture will be 64 or 32 bits. Default: `64`
   
   **-DownloadOnly:** Only downloads the binaries to `C:\temp\`, not installing. Default: `$false`
   
   **-PublicKeyOnly:** Defines if only public key authentication will be enabled. Default: `$false`
   
   **-PublicKey:** Defines if public key authentication will be allowed. Default: `$false`
   
   **-KeyPath:** Defines the path to the key file for using with public key authentication. Default: `$null`

## Issues

If you find any problems, please open an issue at [the issues page](https://github.com/aJesus37/OpenSSH-Config/issues)