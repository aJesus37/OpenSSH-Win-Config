# OpenSSH-Config
A Powershell script to download and config OpenSSH for Windows operating systems.

Uses the latest release of [this](https://github.com/PowerShell/Win32-OpenSSH/) GitHub repo for downloading the OpenSSH binaries.

## Possible flags:

   **-Verbose:** Adds verbosity level to script output. Default: `$false`

   **-Download:** Defines if will try to download the binaries from GitHub or install directly from machine. Default: `$false`

   **-Shell:** Defines if the default shell after ssh into the machine will be cmd or powershell. Default: `powershell`

   **-Architecture:** Defines if the binarie architecture will be 64 or 32 bits. Default: `64`

# Important!

Actual release defines that only public key authentication will be possible. Not usable for password authentication yet, changes will be made in following releases.

The public key must be under `C:\temp\` directory.
