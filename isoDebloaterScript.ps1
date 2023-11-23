# Windows ISO Debloater
# Author: itsNileshHere
# Date: 2023-11-21
# Description: A simple PSscript to modify windows iso file. For more info check README.md


# Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    Exit
}

# Set-ExecutionPolicy unrestricted

Write-Host "Starting Windows ISO Debloater Script ..."
Start-Sleep -Milliseconds 1500
Write-Host
Write-Host "There will be some prompts for the user!"
Start-Sleep -Milliseconds 1500
Write-Host
Write-Host "If you want to whitelist any package, just open the script and comment out the Packagename."
Start-Sleep -Milliseconds 1500

$scriptDirectory = "$PSScriptRoot"
$logFilePath = Join-Path -Path $scriptDirectory -ChildPath 'script_log.txt'
function Write-LogMessage {
    param (
        [string]$message
    )

    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    Add-Content -Path "$logFilePath" -Value $logEntry
}

Write-LogMessage "Script started"
Write-Host
$sourceDriveLetter = Read-Host -Prompt "Enter the drive letter of mounted image"
if (-not (Test-Path "${sourceDriveLetter}:\" -PathType Container)) {
    Write-LogMessage "Invalid source drive: $sourceDriveLetter"
    Exit
}
$sourceDrive = "${sourceDriveLetter}:\"
$destinationPath = "$env:SystemDrive\WIDTemp\winlite"
$mountDirectory = "$env:SystemDrive\WIDTemp\mountdir"
$OscdimgPath = Join-Path -Path $scriptDirectory -ChildPath 'oscdimg.exe'

# Comment out the package don't wanna remove
$packagesToRemove = @(
    'Microsoft.Microsoft3DViewer*',                     # 3DViewer
    'Microsoft.WindowsAlarms*',                         # Alarms
    'Microsoft.BingNews*',                              # Bing News
    'Microsoft.BingWeather*',                           # Bing Weather
    'Clipchamp.Clipchamp*',                             # Clipchamp
    'Microsoft.549981C3F5F10*',                         # Cortana
    'Microsoft.Windows.DevHome*',                       # DevHome
    'MicrosoftCorporationII.MicrosoftFamily*',          # Family
    'Microsoft.WindowsFeedbackHub*',                    # FeedbackHub
    'Microsoft.GetHelp*',                               # GetHelp
    'Microsoft.Getstarted*',                            # GetStarted
    'Microsoft.WindowsCommunicationsapps*',             # Mail
    'Microsoft.WindowsMaps*',                           # Maps
    'Microsoft.MixedReality.Portal*',                   # MixedReality
    'Microsoft.ZuneMusic*',                             # Music
    'Microsoft.MicrosoftOfficeHub*',                    # OfficeHub
    'Microsoft.Office.OneNote*',                        # OneNote
    'Microsoft.OutlookForWindows_*',                    # Outlook
    'Microsoft.MSPaint*',                               # Paint3D(Windows10)
    'Microsoft.People*',                                # People
    'Microsoft.YourPhone*',                             # Phone
    'Microsoft.PowerAutomateDesktop*',                  # PowerAutomate
    'MicrosoftCorporationII.QuickAssist*',              # QuickAssist
    'Microsoft.SkypeApp*',                              # Skype
    'Microsoft.MicrosoftSolitaireCollection*',          # SolitaireCollection
  #  'Microsoft.WindowsSoundRecorder*',                  # SoundRecorder
    'MicrosoftTeams*',                                  # Teams
    'Microsoft.Todos*',                                 # Todos
    'Microsoft.ZuneVideo*',                             # Video
    'Microsoft.Wallet*',                                # Wallet
    'Microsoft.GamingApp*',                             # Xbox
    'Microsoft.XboxApp*',                               # Xbox(Win10)
    'Microsoft.XboxGameOverlay*',                       # XboxGameOverlay
    'Microsoft.XboxGamingOverlay*',                     # XboxGamingOverlay
    'Microsoft.XboxSpeechToTextOverlay*',               # XboxSpeechToTextOverlay
    'Microsoft.Xbox.TCUI*'                              # XboxTCUI
)

$featuresToRemove = @(
    'Browser.InternetExplorer~~~~0.0.11.0',
    'Internet-Explorer-Optional-amd64',
    'App.StepsRecorder~~~~0.0.1.0',
    'Language.Handwriting~~~en-US~0.0.1.0',
    'Language.OCR~~~en-US~0.0.1.0',
    'Language.Speech~~~en-US~0.0.1.0',
    'Language.TextToSpeech~~~en-US~0.0.1.0',
    'Microsoft.Windows.WordPad~~~~0.0.1.0',
    'MathRecognizer~~~~0.0.1.0',
    'Media.WindowsMediaPlayer~~~~0.0.12.0'
)

# Copy Files
Write-Host
Write-Host "Copying files from $sourceDrive to $destinationPath"
Write-LogMessage "Copying files from $sourceDrive to $destinationPath"
$null = New-Item -ItemType Directory -Path $destinationPath
$null = xcopy.exe $sourceDrive $destinationPath /E /I /H /R /Y /J

Write-LogMessage "Getting image info"
Start-Sleep -Milliseconds 500
dism /Get-WimInfo /wimfile:$destinationPath\sources\install.wim
$WimIndex = Read-Host -Prompt "Enter the index to mount"

Write-LogMessage "Mounting image"
try {
    New-Item -ItemType Directory -Path $mountDirectory > $null 2>&1
    dism /mount-image /imagefile:$destinationPath\sources\install.wim /index:$WimIndex /mountdir:$mountDirectory
}
catch {
    Write-LogMessage "Failed to mount image: $_"
    Exit
}

# Remove Packages
Write-LogMessage "Removing provisioned packages"
Write-Host
Write-Host "Removing Packages ..."
Start-Sleep -Milliseconds 1500
foreach ($packageName in $packagesToRemove) {
    try {
        Write-Host "$packageName"
        $provisionedPackages = Get-ProvisionedAppxPackage -Path $mountDirectory | Where-Object { $_.PackageName -like $packageName }
        foreach ($package in $provisionedPackages) {
            $packageNameToRemove = $package.PackageName
            try {
                dism /image:$mountDirectory /Remove-ProvisionedAppxPackage /PackageName:$packageNameToRemove > $null
            }
            catch {
                Write-LogMessage "Removing $packageNameToRemove failed: $_"
            }
        }
    }
    catch {
        Write-LogMessage "Failed to remove provisioned package '$packageName': $_"
    }
}

# Remove useless Features
Write-LogMessage "Removing useless features"
Write-Host
Write-Host "Removing Useless Features ..."
Start-Sleep -Milliseconds 1500
foreach ($feature in $featuresToRemove) {
    try {
        Write-Host "$feature"
        dism /image:$mountDirectory /Remove-Capability /CapabilityName:$feature > $null
    }
    catch {
        Write-LogMessage "Removing $feature failed: $_"
    }
}

Start-Sleep -Milliseconds 1500
Write-Host
Write-Host "Removing OneDrive ..."
Start-Sleep -Milliseconds 1500
Write-LogMessage "Defining OneDrive Setup file paths"
$oneDriveSetupPath1 = Join-Path -Path $mountDirectory -ChildPath 'Windows\System32\OneDriveSetup.exe'
$oneDriveSetupPath2 = Join-Path -Path $mountDirectory -ChildPath 'Windows\SysWOW64\OneDriveSetup.exe'
$oneDriveSetupPath3Pattern = Join-Path -Path $mountDirectory -ChildPath 'Windows\WinSxS\*microsoft-windows-onedrive-setup*\OneDriveSetup.exe'
$oneDriveSetupPath3 = (Get-Item $oneDriveSetupPath3Pattern).FullName
$oneDriveShortcut = Join-Path -Path $mountDirectory -ChildPath 'Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk'
Write-Host "OneDrive Removed"

# Remove OneDrive
Write-LogMessage "Removing OneDrive"
if (Test-Path $oneDriveSetupPath1) {
    takeown /F "$oneDriveSetupPath1" /A > $null 2>&1
    icacls "$oneDriveSetupPath1" /grant:R Administrators:F /T /C > $null 2>&1
    Remove-Item -Path "$oneDriveSetupPath1" -Force > $null 2>&1
}

if (Test-Path $oneDriveSetupPath2) {
    takeown /F "$oneDriveSetupPath2" /A > $null 2>&1
    icacls "$oneDriveSetupPath2" /grant:R Administrators:F /T /C > $null 2>&1
    Remove-Item -Path "$oneDriveSetupPath2" -Force > $null 2>&1
}

if ($null -ne $oneDriveSetupPath3) {
    foreach ($file in $oneDriveSetupPath3) {
        # Write-Host = $file
        takeown /F "$file" /A > $null 2>&1
        icacls "$file" /grant:R Administrators:F /T /C > $null 2>&1
        Remove-Item -Path "$file" -Force > $null 2>&1
    }
}

if (Test-Path $oneDriveShortcut) {
    takeown /F "$oneDriveShortcut" /A > $null 2>&1
    icacls "$oneDriveShortcut" /grant:R Administrators:F /T /C > $null 2>&1
    Remove-Item -Path "$oneDriveShortcut" -Force > $null 2>&1
}

# Remove EDGE
Write-LogMessage "Removing EDGE"
Start-Sleep -Milliseconds 1500
Write-Host
$EdgeConfirm = Read-Host "Do you want to remove Microsoft Edge? (Y/N)"

if ($EdgeConfirm -eq 'Y' -or $EdgeConfirm -eq 'y') {
    Remove-Item -Path "$mountDirectory\Program Files (x86)\Microsoft\Edge" -Recurse -Force > $null 2>&1
    Remove-Item -Path "$mountDirectory\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force > $null 2>&1
    Remove-Item -Path "$mountDirectory\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force > $null 2>&1
    Remove-Item -Path "$mountDirectory\Program Files (x86)\Microsoft\EdgeWebView" -Recurse -Force > $null 2>&1
    Remove-Item -Path "$mountDirectory\ProgramData\Microsoft\EdgeUpdate" -Recurse -Force > $null 2>&1

    # Removing Reg keys
    $softwarePath = Join-Path -Path $mountDirectory -ChildPath 'Windows\System32\config\SOFTWARE'
    $systemPath = Join-Path -Path $mountDirectory -ChildPath 'Windows\System32\config\SYSTEM'
    reg load HKLM\zSOFTWARE $softwarePath >$null
    reg load HKLM\zSYSTEM $systemPath >$null
    reg delete "HKLM\zSOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" /f > $null 2>&1
    reg delete "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Edge" /f > $null 2>&1
    reg delete "HKLM\zSOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" /f > $null 2>&1
    reg delete "HKLM\zSYSTEM\CurrentControlSet\Services\edgeupdate" /f > $null 2>&1
    reg delete "HKLM\zSYSTEM\CurrentControlSet\Services\edgeupdatem" /f > $null 2>&1
    reg unload HKLM\z$softwarePath >$null 2>&1
    reg unload HKLM\z$systemPath >$null 2>&1

    # Removing Task
    $edgeTask = Get-ChildItem -Path "$mountDirectory\Windows\System32\Tasks\MicrosoftEdge*"
    if ($null -ne $edgeTask) {
        foreach ($file in $edgeTask) {
            takeown /F $file /R /D y > $null 2>&1
            icacls $file /grant:R Administrators:F /T /C > $null 2>&1
            Remove-Item -Path $file -Recurse -Force > $null 2>&1
        }
    }

    # For Windows 10 (Legacy EDGE)
    $edge = Get-ChildItem -Path "$mountDirectory\Windows\SystemApps\Microsoft.MicrosoftEdge*"
    if ($null -ne $edge) {
        foreach ($file in $edge) {
            takeown /F $file /R /D y > $null 2>&1
            icacls $file /grant:R Administrators:F /T /C > $null 2>&1
            Remove-Item -Path $file -Recurse -Force > $null 2>&1
        }
    }

    Write-Host "Microsoft Edge has been removed."
} else {
    Write-Host "Microsoft Edge removal cancelled."
    Write-LogMessage "Edge removal cancelled"
}

Start-Sleep -Milliseconds 500
Write-Host
Write-Host "Loading Registry ..."
Write-LogMessage "Defining registry paths"
$componentsPath = Join-Path -Path $mountDirectory -ChildPath 'Windows\System32\config\COMPONENTS'
$defaultPath = Join-Path -Path $mountDirectory -ChildPath 'Windows\System32\config\default'
$ntuserPath = Join-Path -Path $mountDirectory -ChildPath 'Users\Default\ntuser.dat'
$softwarePath = Join-Path -Path $mountDirectory -ChildPath 'Windows\System32\config\SOFTWARE'
$systemPath = Join-Path -Path $mountDirectory -ChildPath 'Windows\System32\config\SYSTEM'

# Load registry
Write-LogMessage "Loading registry"
reg load HKLM\zCOMPONENTS $componentsPath >$null
reg load HKLM\zDEFAULT $defaultPath >$null
reg load HKLM\zNTUSER $ntuserPath >$null
reg load HKLM\zSOFTWARE $softwarePath >$null
reg load HKLM\zSYSTEM $systemPath >$null

# Modify registry settings
Start-Sleep -Milliseconds 1000
Write-Host "Performing Registry Tweaks ..."

# Disable Sponsored Apps
Reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
Reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
Reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
Reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f > $null 2>&1
Reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d '{\"pinnedList\": [{}]}' /f > $null 2>&1
# Disable Telemetry
Reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > $null 2>&1
# Disable privacy review in OOBE
Reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f > $null 2>&1
# Disable Meet Now icon
Reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f > $null 2>&1
Reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f > $null 2>&1
# Disable ad tailoring
Reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f > $null 2>&1
# Disable GameBar
Reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f > $null 2>&1
# Disable Cortana
Reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f > $null 2>&1
# Disables autosync to OneDrive
Reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f > $null 2>&1
# Changes MenuShowDelay from 400 to 200
Reg add "HKLM\zNTUSER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f > $null 2>&1
# Disable everytime MRT download through Win Update
Reg add "HKLM\zSOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f > $null 2>&1
# Disable OneDrive Sync
Reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f > $null 2>&1
Reg add "HKLM\zSOFTWARE\Policies\Microsoft\OneDrive" /v "KFMBlockOptIn" /t REG_DWORD /d "1" /f > $null 2>&1

Start-Sleep -Milliseconds 1500
Write-Host "Unloading Registry ..."
Write-LogMessage "Unloading registry"
foreach ($key in 'COMPONENTS', 'DEFAULT', 'NTUSER', 'SOFTWARE', 'SYSTEM') {
    try {
        reg unload HKLM\z$key >$null 2>&1
    }
    catch {
        Write-LogMessage "Failed to unload registry '$key': $_"
    }
}

Start-Sleep -Milliseconds 1000
Write-Host
Write-Host "Cleaning up image ..."
Write-LogMessage "Cleaning up image"
dism /image:$mountDirectory /Cleanup-Image /StartComponentCleanup /ResetBase

Start-Sleep -Milliseconds 1000
Write-Host
Write-Host "Unmounting and Exporting image ..."
Write-LogMessage "Unmounting image"
try {
    $unmountProcess = Start-Process -FilePath "dism" -ArgumentList "/unmount-image", "/mountdir:$mountDirectory", "/commit" -PassThru -Wait -NoNewWindow
    if ($unmountProcess.ExitCode -ne 0) {
        $errorMessage = "Failed to unmount image. Exit code: $($unmountProcess.ExitCode)"
        Write-LogMessage $errorMessage
        Write-Host
        Write-Host "Failed to Unmount the Image. Check Logs for more info."
        Write-Host "Close all the Folders opened in the mountdir to complete the Script."
        Write-Host "Run the following code in Powershell(as admin) to unmount the broken image: "
        Write-Host "dism /unmount-image /mountdir:$mountDirectory /discard"
        Read-Host -Prompt "Press Enter to exit"
        Write-LogMessage "Exiting Script"
        Exit
    }
}
catch {
    Write-LogMessage "Failed to unmount image: $_"
    Exit
}

Write-LogMessage "Exporting image"
dism /Export-Image /SourceImageFile:$destinationPath\sources\install.wim /SourceIndex:1 /DestinationImageFile:$destinationPath\sources\install2.wim /compress:max

Remove-Item -Path "$destinationPath\sources\install.wim" -Force
Rename-Item -Path "$destinationPath\sources\install2.wim" -NewName "install.wim" -Force

Write-LogMessage "Specifying boot data"
$bootData = '2#p0,e,b"{0}"#pEF,e,b"{1}"' -f "$destinationPath\boot\etfsboot.com", "$destinationPath\efi\Microsoft\boot\efisys.bin"
Write-LogMessage "Boot data set: $bootData"

Write-LogMessage "Checking required files"
Write-Host
$ISOFileName = Read-Host -Prompt "Enter the name for the ISO file (without extension)"
$ISOFile = Join-Path -Path $scriptDirectory -ChildPath "$ISOFileName.iso"

if (-not (Test-Path -Path "$oscdimgPath")) {
    Write-LogMessage "Oscdimg.exe not found at '$oscdimgPath'"
    Write-Host
    Write-Host "Oscdimg.exe not found at '$oscdimgPath'. Exiting ..."
    Start-Sleep -Milliseconds 1800
    Write-Host "Trying to Download oscdimg.exe"

    # Downloading Oscdimg.exe
    $adkUrl = "https://go.microsoft.com/fwlink/?linkid=2243390"
    $downloadPath= "$scriptDirectory\ADKInstaller.exe"
    $installPath = "C:\Program Files (x86)\Windows Kits\10"
    $sourcePath = "$installPath\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg"
    $destinationPath = "$scriptDirectory"

    if (-not (Test-Path -Path "$sourcePath\oscdimg.exe")) {
        Invoke-WebRequest -Uri $adkUrl -OutFile $downloadPath

        Write-Host
        Write-Host "Installing ADK Setup. This may take some time. Do not exit the Script ..."

        # Installing Deployment Tools only
        Start-Process -FilePath $downloadPath -ArgumentList "/quiet /norestart /features OptionId.DeploymentTools" -Wait
    }
    
    Copy-Item -Path "$sourcePath\oscdimg.exe" -Destination $destinationPath -Force
    Remove-Item -Path $downloadPath -Force
    Write-Host "Installed Successfully"
    Start-Sleep -Milliseconds 1000
}

# Generate ISO
Write-Host
Write-Host "Generating ISO ..."
Write-LogMessage "Generating ISO"
try {
    $null = Start-Process -FilePath "$OscdimgPath" -ArgumentList @("-bootdata:$BootData", '-m', '-o', '-u2', '-udfver102', $destinationPath , "$ISOFile") -PassThru -Wait -NoNewWindow
    Write-LogMessage "ISO successfully created"
}
catch {
    Write-LogMessage "Failed to generate ISO with exit code: $_"
}

# Remove temporary files
Write-Host
Write-Host "Removing temporary files ..."
Write-LogMessage "Removing temporary files"
try {
    Remove-Item -Path $destinationPath -Recurse -Force
    Remove-Item -Path $mountDirectory -Recurse -Force
    Remove-Item -Path "$env:SystemDrive\WIDTemp" -Recurse -Force
}
catch {
    Write-LogMessage "Failed to remove temporary files: $_"
}
finally {
    Write-LogMessage "Script completed"
}

Start-Sleep -Milliseconds 1500
Write-Host
Write-Host "Script Completed. You can find the ISO in `"$scriptDirectory"`"
Read-Host -Prompt "Done. Press Enter to exit"
