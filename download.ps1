if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    Exit
}

$scriptUrl = "https://raw.githubusercontent.com/itsNileshHere/Windows-ISO-Debloater/main/isoDebloaterScript.ps1"

$scriptDirectory = "$env:SystemDrive\scriptdir"

if (-not (Test-Path -Path $scriptDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $scriptDirectory > $null 2>&1
}

$scriptPath = Join-Path -Path $scriptDirectory -ChildPath "isoDebloaterScript.ps1"

Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath

& $scriptPath
