<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

<#

For information about this tool, including data it stores to understand effectiveness, go to https://aka.ms/ASR_shortcuts_deletion_FAQ

#>

<#
# script to add deleted shortcuts back for common application.
# Credits & Thanks to:
#           https://github.com/InsideTechnologiesSrl/DefenderBug/blob/main/RestoreLinks.ps1 (Author: Silvio Di Benedetto, Company: Inside Technologies)
#           https://p0w3rsh3ll.wordpress.com/2014/06/21/mount-and-dismount-volume-shadow-copies/ (Author: Emin Atac)
#           https://github.com/microsoft/MDE-PowerBI-Templates/issues/18 (Bug report & suggestion: RobertEbbrecht)
#           https://github.com/microsoft/MDE-PowerBI-Templates/issues/31 (Bug report & suggestion: MeIQL)
#           https://github.com/microsoft/MDE-PowerBI-Templates/issues/35 (Bug report & suggestion: imnota)
#           https://github.com/microsoft/MDE-PowerBI-Templates/issues/32 (Bug report: nserup)
#

Help:

Param Telemetry: enable or disable having telemetry logging, default: true
Param ForceRepair: repair is done irrespective of machine being considered affected or not, default: true
Param VssRecovery: Use VSS recovery to restore lnk files, default: true
Param Verbose:
    Value 0: No stdout and no log file
    Value 1: Only stdout (default)
    Value 2: both stdout and log file output
    Value 3: detailed stdout along with log file output

#>

param ([bool] $Telemetry = $true, [switch] $ForceRepair = $true, [switch] $VssRecovery = $true, [switch] $MpTaskBarRecoverUtilDownload = $true, [switch] $SkipBinaryValidation = $false, [int] $Verbose = 1)

$ScriptVersion = 5
$ScriptVersionStr = "v" + $ScriptVersion.ToString()
$doesCFANeedsReset = $false
$TaskbarRecoveryToolName = "MpRecoverTaskbar.exe"

<#
#  Important: programs table below is a key=value pair, with [] are used to denote programs that have version year info, like [Visual Studio 2022]
#  for such entries with [], we will lookup file description in file version info and use that, if it doesnt exists, we will falback using generic name.
#>

$programs = @{
    "Adobe Acrobat"                = "Acrobat.exe"
    "[Adobe Photoshop]"            = "photoshop.exe"
    "[Adobe Illustrator]"          = "illustrator.exe"
    "Adobe Creative Cloud"         = "Creative Cloud.exe"
    "Adobe Substance 3D Painter"   = "Adobe Substance 3D Painter.exe"
    "Firefox Private Browsing"     = "private_browsing.exe"
    "Firefox"                      = "firefox.exe"
    "Google Chrome"                = "chrome.exe"
    "Microsoft Edge"               = "msedge.exe"
    "Notepad++"                    = "notepad++.exe"
    "Parallels Client"             = "APPServerClient.exe"
    "Remote Desktop"               = "msrdcw.exe"
    "TeamViewer"                   = "TeamViewer.exe"
    "[Royal TS]"                   = "royalts.exe"
    "Elgato StreamDeck"            = "StreamDeck.exe"
    "[Visual Studio]"              = "devenv.exe"
    "Visual Studio Code"           = "code.exe"
    "Camtasia Studio"              = "CamtasiaStudio.exe"
    "Camtasia Recorder"            = "CamtasiaRecorder.exe"
    "Jabra Direct"                 = "jabra-direct.exe"
    "7-Zip File Manager"           = "7zFM.exe"
    "Access"                       = "MSACCESS.EXE"
    "Excel"                        = "EXCEL.EXE"
    "OneDrive"                     = "onedrive.exe"
    "OneNote"                      = "ONENOTE.EXE"
    "Outlook"                      = "OUTLOOK.EXE"
    "PowerPoint"                   = "POWERPNT.EXE"
    "Project"                      = "WINPROJ.EXE"
    "Publisher"                    = "MSPUB.EXE"
    "Visio"                        = "VISIO.EXE"
    "Word"                         = "WINWORD.exe"
    "[PowerShell 7]"               = "pwsh.exe"
    "SQL Server Management Studio" = "ssms.exe"
    "Azure Data Studio"            = "azuredatastudio.exe"
    "Zoom"                         = "zoom.exe"
    "Internet Explorer"            = "IEXPLORE.EXE"
    "Skype for Business"           = "Skype.exe"
    "VLC Player"                   = "vlc.exe"
    "Cisco Jabber"                 = "CiscoJabber.exe"
    "Microsoft Teams"              = "msteams.exe"
    "PuTTY"                        = "putty.exe"
    "wordpad"                      = "WORDPAD.EXE"
    "[AutoCAD]"                    = "acad.exe"
    "[CORSAIR iCUE Software]"      = "iCue.exe"
    "[Steam]"                      = "steam.exe"
    "Paint"                        = "mspaint.exe"
}

$LogFileName = [string]::Format("ShortcutRepairs{0}.log", (Get-Random -Minimum 0 -Maximum 99))
$LogFilePath = "$env:temp\$LogFileName";

Function Log {
    param($message);
    if ($Verbose -ge 2) {
        $currenttime = Get-Date -format u;
        $outputstring = "[" + $currenttime + "] " + $message;
        $outputstring | Out-File $LogFilepath -Append;
    }
}

Function LogAndConsole($message) {
    if ($Verbose -ge 1) {
        Write-Host $message -ForegroundColor Green
    }
    if ($Verbose -ge 2) {
        Log $message
    }
}

Function LogErrorAndConsole($message) {
    if ($Verbose -ge 1) {
        Write-Host $message -ForegroundColor Red
    }
    if ($Verbose -ge 2) {
        Log $message
    }
}

function Get-PSVersion {
    if ($PSVersionTable.PSVersion -like '7*') {
        [string]$PSVersionTable.PSVersion.Major + '.' + [string]$PSVersionTable.PSVersion.Minor + '.' + [string]$PSVersionTable.PSVersion.Patch
    }
    else {
        [string]$PSVersionTable.PSVersion.Major + '.' + [string]$PSVersionTable.PSVersion.Minor + '.' + [string]$PSVersionTable.PSVersion.Build
    }
}

# Saves the result of the script in the registry.
# If you don't want this information to be saved use the -Telemetry $false option
Function SaveResult() {

    param(
        [parameter(ParameterSetName = "Failure")][switch][Alias("Failed")]$script_failed = $false,
        [parameter(ParameterSetName = "Failure")][string][Alias("ScriptError")]$script_error = "Generic Error",
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("NumLinksFound")]$links_found = 0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKUAppsSuccess")]$hku_success = 0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKUAppsFailure")]$hku_failure = 0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKLMAppsSuccess")]$hklm_success = 0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKLMAppsFailure")]$hklm_failure = 0,
        [parameter(ParameterSetName = "Success")][switch][Alias("Succeeded")]$script_succeeded = $false,
        [parameter(ParameterSetName = "Success")][parameter(ParameterSetName = "Failure")][Alias("User")][switch]$use_hkcu = $false
    )

    if ($use_hkcu) {
        $registry_hive = "HKCU:"
    }
    else {
        $registry_hive = "HKLM:"
    }
    $registry_hive += "Software\Microsoft"
    $registry_name = "ASRFix"

    if ($Telemetry) {

        $registry_full_path = $registry_hive + "\" + $registry_name

        if (Test-Path -Path $registry_full_path) {
            #Registry Exists
        }
        else {
            #Registry does not Exist, create it
            New-Item -Path $registry_hive -Name $registry_name -Force | Out-Null

        }

        #Create a timestamp
        $timestamp = [DateTime]::UtcNow.ToString('o')

        #If its a success, make sure there is no error left over from last run
        if ($PsCmdlet.ParameterSetName -eq "Success") {
            $script_error = "None"
            $result = "Success"
            $script_result = 0
        }
        else {
            $result = "Failure"
            $script_result = 1
        }

        #Save the result in the registry
        New-ItemProperty -Path $registry_full_path -Name Version -Value $ScriptVersion -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name ScriptResult -Value $script_result -Force -PropertyType DWORD | Out-Null
        New-ItemProperty -Path $registry_full_path -Name Timestamp -Value $timestamp -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name NumLinksFound -Value $links_found -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKUAppSuccess -Value $hku_success -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKUAppFailure -Value $hku_failure -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKLMSuccess -Value $hklm_success -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKLMFailure -Value $hklm_failure -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name ScriptError -Value $script_error -Force | Out-Null

        if ($Verbose -ge 1) {
            LogAndConsole "[+] Saved Result: ScriptResult=$result ($script_result), TimeStamp=$timestamp`n`tNumLinksFound=$links_found, HKUAppSuccess=$hku_success, HKUAppFailure=$hku_failure, HKLMSuccess=$hklm_success, HKLMFailure=$hklm_failure`n`tScriptError=`"$script_error`"`n`tSaved in registry $registry_full_path"
        }
    }
}

#If there is any error, save the result as a failure
trap {

    if ($doesCFANeedsReset) {
        # turn it back on
        LogAndConsole "[+] Turn CFA back ON to its original state"
        Set-MpPreference -EnableControlledFolderAccess 1
        $doesCFANeedsReset = $false
    }

    $script_error = ""
    if ($_) {
        $script_error = $_.ToString() + " at line $($_.InvocationInfo.ScriptLineNumber)"
    }

    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (!($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -Or ($id.Name -like "NT AUTHORITY\SYSTEM"))) {
        SaveResult -Failed -User -ScriptError $script_error
    }
    else {
        SaveResult -Failed -ScriptError $script_error
    }

    exit
}

Function Mount-VolumeShadowCopy {
    <#
    .SYNOPSIS
        Mount a volume shadow copy.

    .DESCRIPTION
        Mount a volume shadow copy.

    .PARAMETER ShadowPath
        Path of volume shadow copies submitted as an array of strings

    .PARAMETER Destination
        Target folder that will contain mounted volume shadow copies

    .EXAMPLE
        Get-CimInstance -ClassName Win32_ShadowCopy |
        Mount-VolumeShadowCopy -Destination C:\VSS -Verbose

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidatePattern('\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d{1,}')]
        [Alias("DeviceObject")]
        [String[]]$ShadowPath,

        [Parameter(Mandatory)]
        [ValidateScript({
                Test-Path -Path $_ -PathType Container
            }
        )]
        [String]$Destination
    )
    Begin {
        Try {
            $null = [mklink.symlink]
        }
        Catch {
            Add-Type @"
        using System;
        using System.Runtime.InteropServices;

        namespace mklink
        {
            public class symlink
            {
                [DllImport("kernel32.dll")]
                public static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
            }
        }
"@
        }
    }
    Process {

        $ShadowPath | ForEach-Object -Process {

            if ($($_).EndsWith("\")) {
                $sPath = $_
            }
            else {
                $sPath = "$($_)\"
            }

            $tPath = Join-Path -Path $Destination -ChildPath (
                '{0}-{1}' -f (Split-Path -Path $sPath -Leaf), [GUID]::NewGuid().Guid
            )

            try {
                if (
                    [mklink.symlink]::CreateSymbolicLink($tPath, $sPath, 1)
                ) {
                    LogAndConsole "`tSuccessfully mounted $sPath to $tPath"
                    return $tPath
                }
                else {
                    LogAndConsole "[!] Failed to mount $sPath"
                }
            }
            catch {
                LogAndConsole "[!] Failed to mount $sPath because $($_.Exception.Message)"
            }
        }

    }
    End {}
}


Function Dismount-VolumeShadowCopy {
    <#
    .SYNOPSIS
        Dismount a volume shadow copy.

    .DESCRIPTION
        Dismount a volume shadow copy.

    .PARAMETER Path
        Path of volume shadow copies mount points submitted as an array of strings

    .EXAMPLE
        Get-ChildItem -Path C:\VSS | Dismount-VolumeShadowCopy -Verbose


#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("FullName")]
        [string[]]$Path
    )
    Begin {
    }
    Process {
        $Path | ForEach-Object -Process {
            $sPath = $_
            if (Test-Path -Path $sPath -PathType Container) {
                if ((Get-Item -Path $sPath).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    try {
                        [System.IO.Directory]::Delete($sPath, $false) | Out-Null
                        LogAndConsole "`tSuccessfully dismounted $sPath"
                    }
                    catch {
                        LogAndConsole "[!] Failed to dismount $sPath because $($_.Exception.Message)"
                    }
                }
                else {
                    LogAndConsole "[!] The path $sPath isn't a reparsepoint"
                }
            }
            else {
                LogAndConsole "[!] The path $sPath isn't a directory"
            }
        }
    }
    End {}
}

Function GetTimeRangeOfVersion() {

    $versions = "1.381.2140.0", "1.381.2152.0", "1.381.2160.0"

    $properties2000 = @(
        'TimeCreated',
        'ProductName',
        'ProductVersion',
        @{n = 'CurrentVersion'; e = { $_.Properties[2].Value } },
        @{n = 'PreviousVersion'; e = { $_.Properties[3].Value } })


    $installTime = $null
    $removalTime = $null
    $foundVersion = $null

    try {
        foreach ($version in $versions) {

            if ($null -eq $installTime) {
                $lgp_events = (Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | where { $_.Id -eq 2000 } | Select $properties2000 | Where-Object { $_.CurrentVersion -eq $($version) } )
                if ($lgp_events) {
                    $installTime = @($lgp_events[0]).TimeCreated
                    $foundVersion = $version
                }
            }
            $rgp_events = (Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | where { $_.Id -eq 2000 } | Select $properties2000 | Where-Object { $_.PreviousVersion -eq $($version) } )
            if ($rgp_events) {
                $removalTime = @($rgp_events[0]).TimeCreated
            }
        }
        if ($installTime ) {
            if ($removalTime) {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tInstall time $installTime, removal time $removalTime for build $foundVersion"
                }
            }
            else {
                if ($Verbose -gt 2) {
                    LogAndConsole "[!] Broken build version $foundVersion is still installed! First update to a build >= 1.381.2164.0 and run again."
                }
            }
        }
        else {
            LogAndConsole "[+] Machine impact detection is inconclusive"
        }
    }
    catch {
        if ($Verbose -gt 2) {
            LogAndConsole "[!] Failed to find broken build version."
        }
    }

    if ($null -eq $installTime) {
        # We couldn't find broken build version, vss recovery will be enforced by hardcoded date we have from VDM release time
        $installTime = '2023-01-13T06:04:45.000Z'

        # convert UTC to current date
        $installTime = ([DateTime]$installTime).ToUniversalTime()
        $installTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($installTime, 'UTC', [System.TimeZoneInfo]::Local.Id)
    }

    return $installTime, $removalTime , $foundVersion
}

#check if Server SKU or not
Function IsServerSKU {

    try {
        return ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 1)
    }
    catch {
        return (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels")
    }
}

#find shadow copy before bad update
Function GetShadowcopyBeforeUpdate( $targetDate ) {

    $shadowCopies = $null
    $shadowcopies = Get-WmiObject Win32_shadowcopy | Where-Object { [System.Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate) -lt $targetDate } | Sort-Object InstallDate -Descending

    $driveDict = @{}
    foreach ($shadow in $shadowcopies ) {
        LogAndConsole "$($shadow.VolumeName) $($shadow.DeviceObject) $($shadow.InstallDate)  $($shadow.CreationTime)"
        # this is intentional, to replace \ with \\
        $escapedDrive = $shadow.VolumeName -replace '\\', '\\'
        $volume = Get-WmiObject -Class Win32_Volume -Namespace "root\cimv2" -Filter "DeviceID='$escapedDrive'"

        if ($null -eq $driveDict[$volume.DriveLetter]) {
            $driveDict[$volume.DriveLetter] = @()
        }
        $driveDict[$volume.DriveLetter] += $shadow
    }

    return $driveDict
}

function getAllValidExtsForDrive($path, $drive, $prefix, $extension) {
    $prefixLen = $($path).length

    LogAndConsole "[+] Listing $($extension) for $($path)\$($prefix)*"
    $extFiles = Get-ChildItem -ErrorAction SilentlyContinue -Path "$path\$($prefix)*" -Include "*$($extension)" -Recurse -Force
    if ($Verbose -gt 2) {
        LogAndConsole "`tNow analyzing ($extension) files..."
    }

    if ($extFiles) {
        $validFiles = @()
        foreach ($extFile in $extFiles) {
            if ($Verbose -gt 2) {
                LogAndConsole "`tFound $($extension): $($extFile.FullName)"
            }
            $drivePath = $drive + $extFile.FullName.Substring($prefixLen)
            try {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tChecking original: $($drivePath)"
                }
                $originalLink = Get-Item -Path $drivePath -ErrorAction Stop
            }
            catch {
                Copy-Item -Path $extFile.FullName -Destination $drivePath
                if ($Verbose -gt 2) {
                    LogAndConsole "`tOriginal path doesn't exist anymore: $($drivePath)"
                }
                $validFiles += $extFile
            }
        }
        return $validFiles
    }
}

function getAllValidLNKsForDrive($path, $drive, $prefix) {
    $prefixLen = $($path).length

    LogAndConsole "[+] Listing .lnk for $path\$($prefix)*"
    $lnkFiles = Get-ChildItem -ErrorAction SilentlyContinue -Path "$path\$($prefix)*" -Include "*.lnk" -Recurse -Force
    if ($Verbose -gt 2) {
        LogAndConsole "`tNow analyzing .lnk files..."
    }

    if ($lnkFiles) {
        $validLinks = @()
        foreach ($lnkFile in $lnkFiles) {
            try {
                $target = (New-Object -ComObject WScript.Shell).CreateShortcut($lnkFile.FullName).TargetPath
                $targetFile = Get-Item -Path $target -ErrorAction Stop
            }
            catch {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tThe target of $($lnkFile.FullName) does not exist. Skipped!"
                }
            }
            if ($Verbose -gt 2) {
                LogAndConsole "`tFound LNK: $($lnkFile.FullName)"
            }
            $drivePath = $drive + $lnkFile.FullName.Substring($prefixLen)
            try {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tChecking original: $($drivePath)"
                }
                $originalLink = Get-Item -Path $drivePath -ErrorAction Stop
            }
            catch {
                if ($Verbose -gt 2) {
                    LogAndConsole "`tOriginal path doesn't exist anymore: $($drivePath)"
                }
                Copy-Item -Path $lnkFile.FullName -Destination $drivePath
                $validLinks += $lnkFile
            }
        }
        return $validLinks
    }
}

Function VssFileRecovery($events_time) {
    LogAndConsole "[+] Starting vss file recovery"
    $lnks = @()
    if ($events_time) {
        if ($Verbose -gt 2) {
            LogAndConsole ("`tStart time of update: $($events_time[0])")
            LogAndConsole ("`tEnd time of update: $($events_time[1])")
        }

        LogAndConsole "[+] Attempting vss file recovery by looking for shadow copies before time: $($events_time[0])"

        $missed_drives = @{}
        $guid = New-Guid
        $target = "$env:SystemDrive\vssrecovery-$guid\"
        try {
            $shadowcopies = GetShadowcopyBeforeUpdate( $events_time[0])
            if ($shadowcopies) {
                # create a directory for vss mount
                New-Item -Path $target -ItemType Directory -force | Out-Null
                # get list of profiles that have been modified within range
                $localUsersPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name ProfilesDirectory

                $profiles = Get-ChildItem -Path $localUsersPath -Force
                LogAndConsole "[+] Start recovering profiles"
                foreach ($profilename in $profiles) {
                    $profiledir = (Split-Path $profilename.FullName -NoQualifier).Trim("\").ToString()
                    $drive = Split-Path $profilename.FullName -Qualifier

                    if ($null -ne $shadowCopies[$drive]) {
                        $shadowCopy = $shadowCopies[$drive][0]
                        if ($Verbose -gt 2) {
                            LogAndConsole "`tRestoring items for drive $drive and profile $profilename"
                        }
                        LogAndConsole $($shadowCopy.DeviceObject)
                        $res = Mount-VolumeShadowCopy $shadowCopy.DeviceObject -Destination $target -Verbose

                        if ($Verbose -gt 2) {
                            LogAndConsole "`tNow enumerating for $($profiledir)"
                        }

                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\"
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "\ProgramData\Microsoft\Windows\Start Menu\"
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Windows\"
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Internet Explorer\"
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Office\"
                        $lnks += getAllValidExtsForDrive -path $res -drive $drive -prefix "$($profiledir)\Favorites\" -extension ".url"
                        $lnks += getAllValidExtsForDrive -path $res -drive $drive -prefix "$($profiledir)\Desktop\" -extension ".url"
                        $lnks += getAllValidLNKSForDrive -path $res -drive $drive -prefix "$($profiledir)\Desktop\"
                        Get-ChildItem -Path $target | Dismount-VolumeShadowCopy -Verbose
                    }
                    else {
                        if ($null -eq $missed_drives[$drive]) {
                            $missed_drives[$drive] = 1
                            if ($Verbose -gt 2) {
                                LogAndConsole ("[!] No shadow copy could be found before update for $drive, unable to do VSS recovery for it, skipping!")
                            }
                        }
                    }
                }
                if ($Verbose -gt 2) {
                    if ($lnks) {
                        LogAndConsole "`tRecovered Links from VSS: $($lnks)"
                    }
                    else {
                        LogAndConsole "[!] No .lnk and .url files were found in the shadow copy"
                    }
                }
                #remove vss directory
                Remove-Item -Path $target -Recurse -force | Out-Null
            }
            else {
                LogAndConsole ("[!] No shadow copy could be found before update, unable to do VSS recovery, proceeding with re-creation attempt on Known apps!")
            }
        }
        catch {
            LogErrorAndConsole "[!] VSSRecovery failed!"
            #remove vss directory
            if (Test-Path -Path $target) {
                Remove-Item -Path $target -Recurse -force | Out-Null
            }
        }
    }
    return $lnks.Length
}

Function CopyAclFromOwningDir($path, $SetAdminsOwner) {
    $base_path = Split-Path -Path $path
    $acl = Get-Acl $base_path
    if ($SetAdminsOwner) {
        $SID = "S-1-5-32-544"
        $group = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount])
        $acl.SetOwner($group)
    }
    Set-Acl $path $acl
}

Function LookupHKLMAppsFixLnks($programslist) {
    $success = 0
    $failures = 0
    $programslist.GetEnumerator() | ForEach-Object {
        $reg_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($_.Value)"
        try {
            $apppath = $null
            $target = $null
            try { $apppath = Get-ItemPropertyValue $reg_path -Name "Path" -ErrorAction SilentlyContinue } catch {}
            if ($null -ne $apppath) {
                if ($apppath.EndsWith(";") -eq $true) {
                    $apppath = $apppath.Trim(";")
                }
                if ($apppath.EndsWith("\") -eq $false) {
                    $apppath = $apppath + "\"
                }
                $target = $apppath + $_.Value
            }
            else {
                try { $target = Get-ItemPropertyValue $reg_path -Name "(default)" -ErrorAction SilentlyContinue } catch {}
            }

            if ($null -ne $target) {
                $targetName = $_.Key
                $target = $target.Trim("`"")

                if ($targetName.StartsWith("[") -and $targetName.EndsWith("]")) {
                    try {
                        $targetNameInVersion = (Get-Item -Path $target).VersionInfo.FileDescription.Trim()
                        if ($targetNameInVersion) {
                            $targetName = $targetNameInVersion
                        }
                    }
                    catch {
                        $targetName = $_.Key.Trim("][")
                    }
                }

                $shortcut_path = "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\$($targetName).lnk"

                if (-not (Test-Path -Path $shortcut_path)) {
                    LogAndConsole ("`tShortcut for {0} not found in \Start Menu\, creating it now." -f $targetName)
                    $description = $targetName
                    $workingdirectory = (Get-ChildItem $target).DirectoryName
                    $WshShell = New-Object -ComObject WScript.Shell
                    $Shortcut = $WshShell.CreateShortcut($shortcut_path)
                    $Shortcut.TargetPath = $target
                    $Shortcut.Description = $description
                    $shortcut.WorkingDirectory = $workingdirectory
                    $Shortcut.Save()
                    Start-Sleep -Seconds 1          # Let the LNK file be backed to disk
                    if ($Verbose -gt 2) {
                        LogAndConsole "`tCopying ACL from owning folder"
                    }
                    CopyAclFromOwningDir $shortcut_path $True
                    $success += 1
                }
            }
        }
        catch {
            $failures += 1
            LogErrorAndConsole "Exception: $_"
        }
    }

    return $success, $failures
}

Function LookupHKUAppsFixLnks($programslist) {
    $success = 0
    $failures = 0
    $guid = New-Guid
    New-PSDrive -PSProvider Registry -Name $guid -Root HKEY_USERS -Scope Global | Out-Null
    $users = Get-ChildItem -Path "${guid}:\"
    foreach ($user in $users) {
        # Skip builtin
        if ($user.Name.Contains(".DEFAULT") -or $user.Name.EndsWith("_Classes")) {
            continue;
        }
        $sid_string = $user.Name.Split("\")[-1]

        ## Get the user profile path
        $profile_path = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid_string" -Name "ProfileImagePath").ProfileImagePath
        $programslist.GetEnumerator() | ForEach-Object {
            $reg_path = "${user}\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($_.Value)"
            try {
                $apppath = $null
                $target = $null
                try { $apppath = Get-ItemPropertyValue Registry::$reg_path -Name "Path" -ErrorAction SilentlyContinue } catch {}

                if ($null -ne $apppath) {
                    if ($apppath.EndsWith(";") -eq $true) {
                        $apppath = $apppath.Trim(";")
                    }
                    if ($apppath.EndsWith("\") -eq $false) {
                        $apppath = $apppath + "\"
                    }
                    $target = $apppath + $_.Value
                }
                else {
                    try { $target = Get-ItemPropertyValue Registry::$reg_path -Name "(default)" -ErrorAction SilentlyContinue } catch {}
                }

                if ($null -ne $target) {

                    $targetName = $_.Key
                    $target = $target.Trim("`"")

                    if ($targetName.StartsWith("[") -and $targetName.EndsWith("]")) {
                        try {
                            $targetNameInVersion = (Get-Item -Path $target).VersionInfo.FileDescription.Trim()
                            if ($targetNameInVersion) {
                                $targetName = $targetNameInVersion
                            }
                        }
                        catch {
                            $targetName = $_.Key.Trim("][")
                        }
                    }

                    $shortcut_path = "$profile_path\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($targetName).lnk"

                    if (-not (Test-Path -Path $shortcut_path)) {
                        LogAndConsole ("`tShortcut for {0} not found in \Start Menu\, creating it now." -f $targetName)
                        $description = $targetName
                        $workingdirectory = (Get-ChildItem $target).DirectoryName
                        $WshShell = New-Object -ComObject WScript.Shell
                        $Shortcut = $WshShell.CreateShortcut($shortcut_path)
                        $Shortcut.TargetPath = $target
                        $Shortcut.Description = $description
                        $shortcut.WorkingDirectory = $workingdirectory
                        $Shortcut.Save()
                        Start-Sleep -Seconds 1          # Let the LNK file be backed to disk
                        if ($Verbose -gt 2) {
                            LogAndConsole "`tCopying ACL from owning folder"
                        }
                        CopyAclFromOwningDir $shortcut_path $False
                        $success += 1
                    }
                }
            }
            catch {
                $failures += 1
                LogErrorAndConsole "Exception: $_"
            }
        }
    }
    Remove-PSDrive -Name $guid | Out-Null
    return $success, $failures
}


Function IsValidBinary($taskpath) {

    # Optionally skip checks
    if ($SkipBinaryValidation) {
        return $true
    }

    # Validate authenticode
    $validatesig = Get-AuthenticodeSignature -FilePath $taskpath
    if ($Verbose -ge 3) {
        LogAndConsole "[+] $TaskbarRecoveryToolName Signature info: $validatesig"
    }

    if ($validatesig.Status -ne "Valid") {
        LogErrorAndConsole "[!] Failed to validate $TaskbarRecoveryToolName certificate status"
        return $false
    }

    # Need to change for new binaries
    if ($validatesig.SignerCertificate.Thumbprint -ne "63D7FBC20CD3AAB3AC663F465532AF9DCB8BBA33") {
        LogErrorAndConsole "[!] Failed to validate $TaskbarRecoveryToolName SignerCertificate"
        return $false
    }

    # Need to update the version info here
    $verinfo = (Get-Item $Taskpath).VersionInfo
    if ($Verbose -ge 3) {
        LogAndConsole "`t$TaskbarRecoveryToolName version info: $verinfo"
    }

    if ($verinfo.VersionString -lt 1.1.20029.0) {
        LogErrorAndConsole "[!] Failed to validate $TaskbarRecoveryToolName Version String"
        return $false
    }

    if ($verinfo.OriginalFilename -ne $TaskbarRecoveryToolName) {
        LogErrorAndConsole "[!] Failed to validate OriginalFilename of $TaskbarRecoveryToolName"
        return $false
    }

    if ($verinfo.InternalName -ne $TaskbarRecoveryToolName) {
        LogErrorAndConsole "[!] Failed to validate InternalName of $TaskbarRecoveryToolName"
        return $false
    }

    return $true
}

Function HandleMpTaskBarRecoverUtilRunOnce([bool]$download, [bool]$skipToolCopy) {

    try {

        # Define the utility tool
        $util_path = "$env:windir\$TaskbarRecoveryToolName"

        # Optionally completely skip tool being copied
        if (-not ($skipToolCopy))
        {

            # Handle local case
            if (-not $download) {
                # Copy locally from CWD
                $src_path = Join-Path -Path (Get-Location) -ChildPath $TaskbarRecoveryToolName

                # Validate tool authenticity
                if (-not (IsValidBinary($src_path))) {
                    LogAndConsole "[!] Failed to validate '$src_path' authenticity, skipping automatic use RunOnce for $TaskbarRecoveryToolName"
                    return
                }
                elseif (-not $SkipBinaryValidation) {
                    LogAndConsole "`t$TaskbarRecoveryToolName Passed Digital Thumbprint signature validation"
                }

                Copy-Item -Path $src_path -Destination $util_path -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path $util_path)) {
                    LogAndConsole "[!] Could not copy $TaskbarRecoveryToolName from current working directory to '$util_path'"
                    return
                }
            }
            else {
                $util_download_url = "https://aka.ms/ASRTaskBarRepairTool"
                $wc = New-Object System.Net.WebClient
                try {
                    $wc.DownloadFile($util_download_url, $util_path)
                }
                catch {
                    LogAndConsole "[!] Could not download $TaskbarRecoveryToolName from '$util_download_url' to '$util_path'"
                    return
                }
                # Validate tool authenticity
                if (-not (IsValidBinary($util_path))) {
                    LogAndConsole "[!] Failed to validate '$util_path' authenticity, skipping automatic use RunOnce for $TaskbarRecoveryToolName"
                    return
                }
                elseif (-not $SkipBinaryValidation) {
                    LogAndConsole "`t$TaskbarRecoveryToolName Passed Digital Thumbprint signature validation"
                }
            }
        }

        # Register all user's RunOnce by traversing HKU
        $guid = New-Guid
        New-PSDrive -PSProvider Registry -Name $guid -Root HKEY_USERS -Scope Global | Out-Null
        $users = Get-ChildItem -Path "${guid}:\"
        foreach ($user in $users) {
            # Skip builtin
            $user_sid = $user.Name.Split("\")[-1]

            if ($user_sid.Contains(".DEFAULT") -or $user_sid.EndsWith("_Classes")) {
                if ($Verbose -ge 3) {
                    LogAndConsole "`tSkipping $user_sid"
                }
                continue;
            }

            try {
                $fullprofile = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$user_sid" -Name FullProfile
                if ($fullprofile -eq 1) {
                    LogAndConsole "[+] Attempting RunOnce Registration for SID $user_sid"
                }
            }
            catch {
                if ($Verbose -ge 3) {
                    LogAndConsole "`tSkipping $user_sid"
                }
                continue;
            }

            # Register RunOnce entry
            try {
                $RunOnceCmd = "`"$util_path`""
                if ($ForceRepair) {
                    $RunOnceCmd = $RunOnceCmd + " --force"
                }
                if ($Telemetry -ne $true) {
                    $RunOnceCmd = $RunOnceCmd + " --notelemetry"
                }

                $RunOncePath = "${guid}:\$user_sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                if (-not (Test-Path -Path $RunOncePath)) {
                    $res = New-Item -Path "${guid}:\$user_sid\Software\Microsoft\Windows\CurrentVersion" -Name "RunOnce" -Force -ErrorAction SilentlyContinue
                    if ($null -eq $res) {
                        LogAndConsole "[!] RunOnce Key not found for SID $user_sid, unable to auto-create it"
                    }
                }

                $res = New-ItemProperty -Path $RunOncePath -Name "MpTaskBarRecover" -Value $RunOnceCmd -Force -ErrorAction SilentlyContinue
                if ($null -eq $res) {
                    LogAndConsole "[!] Failed registering RunOnce key for SID $user_sid"
                }
                else {
                    LogAndConsole "[+] Successfully registered RunOnce key for SID $user_sid"
                }
            }
            catch {
                LogAndConsole "[!] Failed registering RunOnce key for SID $user_sid"
            }

        }
        Remove-PSDrive -Name $guid | Out-Null
    }
    catch {
        LogErrorAndConsole "Exception: $_"
    }
}

try {[void] [RunAsClass] } catch {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

public static class RunAsClass
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(
        ProcessAccessFlags processAccess,
        bool bInheritHandle,
        uint processId
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();
    
    [DllImport("advapi32.dll")]
    static extern bool LookupPrivilegeValue(
        IntPtr lpSystemName,
        string lpName,
        ref LUID lpLuid
    );

    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        TokenAccessFlags DesiredAccess,
        out IntPtr TokenHandle
    );

    [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        TokenAccessFlags dwDesiredAccess,
        IntPtr lpThreadAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType,
        out IntPtr phNewToken
    );
    
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        UInt32 Zero,
        IntPtr Null1,
        IntPtr Null2
    );
    
    [DllImport("userenv.dll", SetLastError=true)]
    static extern bool CreateEnvironmentBlock(
        out IntPtr lpEnvironment,
        IntPtr hToken,
        bool bInherit
    );
    
    [DllImport("userenv.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DestroyEnvironmentBlock(
        IntPtr lpEnvironment
    );

    [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool CreateProcessAsUserW(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        CreationFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    [SuppressUnmanagedCodeSecurity]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [Flags]
    enum CreationFlags
    {
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    }

    [Flags()]
    enum TokenAccessFlags : int
    {
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY = 0x0008,
        TOKEN_QUERY_SOURCE = 0x0010,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
        TOKEN_ADJUST_GROUPS = 0x0040,
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
        TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID)
    }

    [Flags()]
    enum ProcessAccessFlags : int
    {
        AllAccess = CreateThread | DuplicateHandle | QueryInformation | SetInformation
            | Terminate | VMOperation | VMRead | VMWrite | Synchronize,
        CreateThread = 0x2,
        DuplicateHandle = 0x40,
        QueryInformation = 0x400,
        SetInformation = 0x200,
        Terminate = 0x1,
        VMOperation = 0x8,
        VMRead = 0x10,
        VMWrite = 0x20,
        Synchronize = 0x100000
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public uint HighPart;
    }
    
    struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public LUID Luid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    static void CloseHandleSafe(IntPtr handle)
    {
        if (IntPtr.Zero != handle)
        {
            CloseHandle(handle);
        }
    }
    
    public static string AdjustNamedPriv(string priv)
    {
        string result = "";
        IntPtr hToken = IntPtr.Zero;
        
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES , out hToken))
            {
                throw new Exception("Cannot open process token");
            }
            
            LUID luid = new LUID();
            if (!LookupPrivilegeValue(IntPtr.Zero, priv, ref luid))
            {
                throw new Exception("Cannot lookup token privileges for " + priv);
            }
            
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Luid = luid;
            tp.Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED
            
            if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            {
                throw new Exception("Cannot enable token privileges for " + priv);
            }
        }
        catch (Exception e)
        {
            result = e.Message;
        }

        CloseHandleSafe(hToken);
        return result;
    }

    public static string RunAs(uint processId, string path, string args, ref bool warnAndBailOut)
    {
        warnAndBailOut = false;
        string result = string.Empty;
        IntPtr hProc = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr hDupToken = IntPtr.Zero;
        IntPtr hEnv = IntPtr.Zero;
        PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
        try
        {
            // Open foreign process
            hProc = OpenProcess(ProcessAccessFlags.QueryInformation, false, (uint)processId);
            if (IntPtr.Zero == hProc)
            {
                throw new Exception("Cannot open process");
            }

            // Fetch the foreign process token
            TokenAccessFlags tokenAccess = TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ASSIGN_PRIMARY | TokenAccessFlags.TOKEN_DUPLICATE | TokenAccessFlags.TOKEN_ADJUST_DEFAULT | TokenAccessFlags.TOKEN_ADJUST_SESSIONID;
            if (!OpenProcessToken(hProc, tokenAccess, out hToken))
            {
                throw new Exception("Cannot open process token");
            }

            // Duplicate token
            if (!DuplicateTokenEx(hToken, tokenAccess, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out hDupToken))
            {
                throw new Exception("Cannot duplicate token");
            }
            
            // Create environment block
            if (!CreateEnvironmentBlock(out hEnv, hToken, false))
            {
                throw new Exception("Cannot create environment block");
            }

            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "";
            if (!CreateProcessAsUserW(hDupToken, path, path + " " + args, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.CREATE_UNICODE_ENVIRONMENT, hEnv, null, ref startupInfo, out processInfo))
            {
                int lastErr = Marshal.GetLastWin32Error();
                warnAndBailOut = (1314 == lastErr);
                throw new Exception("Cannot run process as user (error " + lastErr.ToString() + ")");
            }
        }
        catch (Exception e)
        {
            result = e.Message;
        }

        CloseHandleSafe(processInfo.hProcess);
        CloseHandleSafe(processInfo.hThread);
        if (IntPtr.Zero == hEnv)
        {
            DestroyEnvironmentBlock(hEnv);
        }
        CloseHandleSafe(hDupToken);
        CloseHandleSafe(hToken);
        CloseHandleSafe(hProc);
        return result;
    }
}
"@
}

Function TriggerRunOnceForLoggedOnUsers {

    LogAndConsole "[+] Adjusting self token privileges"
    $privs = @("SeDebugPrivilege", "SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege")
    foreach ($priv in $privs)
    {
        $msg = [RunAsClass]::AdjustNamedPriv($priv)
        if ($msg -eq "") {
            if ($Verbose -ge 3) {
                LogAndConsole "[+] Successfully enabled privilege $priv"
            }
        }
        else {
            if ($Verbose -ge 3) {
                LogAndConsole "[+] Failed enabling privilege $priv ($msg), bailing out"
            }
            LogAndConsole "Best effort attempt to trigger $TaskbarRecoveryToolName was unsuccessful. This will be triggered automatically the next time the users logs in."
            return
        }
    }

    LogAndConsole "[+] Attempting Automatic RunOnce trigger on All Users"
    $usr_cnt_success = 0
    $explorer_instances = Get-Process | Where-Object { $_.ProcessName -eq "explorer" -and $_.Modules[0].ModuleName -eq "explorer.exe" }
    foreach ($explorer_instance in $explorer_instances) {
        $proc_id = $explorer_instance.Id
        $warnAndBailOut = $false
        $msg = [RunAsClass]::RunAs($proc_id, "$env:windir\system32\runonce.exe", "/AlternateShellStartup", [ref] $warnAndBailOut);
        if ($msg -eq "") {
            $usr_cnt_success = $usr_cnt_success + 1
            if ($Verbose -ge 3) {
                LogAndConsole "[+] Successfully triggered $TaskbarRecoveryToolName execution for process $proc_id"
            }
        }
        else {
            if ($warnAndBailOut) {
                if ($Verbose -ge 3) {
                    LogAndConsole "`tFailed triggering $TaskbarRecoveryToolName execution for process $proc_id ($msg), bailing out gracefully"
                }
                break
            }
        }
    }
    $total_users = $explorer_instances.Count
    $usr_cnt_failed = $total_users - $usr_cnt_success
    LogAndConsole "`tTriggered automatic $TaskbarRecoveryToolName execution on $usr_cnt_success users and was unsuccessful for $usr_cnt_failed users."
    if ($usr_cnt_failed -gt 0) {
        LogAndConsole "Best effort attempt to trigger $TaskbarRecoveryToolName was unsuccessful for some users. This will be triggered automatically the next time the users logs in."
    }
}

# Main Start
# Validate elevated privileges
LogAndConsole "[+] Starting LNK rescue - Script version: $ScriptVersionStr"
try {
    $selfhash = (Get-FileHash -Algorithm:Sha1 $MyInvocation.MyCommand.Path).Hash
    LogAndConsole "`tScript hash: $selfhash"
}
catch {}

LogAndConsole "`tPowerShell Version: $(Get-PSVersion)"

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if (!($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -Or ($id.Name -like "NT AUTHORITY\SYSTEM"))) {
    LogErrorAndConsole "[!] Not running from an elevated context"
    throw "[!] Please run this script from an elevated PowerShell as Admin or as System"
    exit
}

$isserver = IsServerSKU
if ($isserver -and (-not $ForceRepair)) {
    LogAndConsole "[+] Server SKU didnt get affected, if repair is still needed, please run script again with parameter -ForceRepair"
    exit
}

# Is Machine Affected Check, continue if $ForceRepair is true
$events_time = GetTimeRangeOfVersion
if (-Not ($ForceRepair -or (($null -ne $events_time) -and ($null -ne $events_time[2])))) {
    LogAndConsole "[+] Machine check is inconclusive"
    exit
}
else {
    if ($ForceRepair) {
        LogAndConsole "[+] Attempting ForceRepair"
    }
}

try {
    $doesCFANeedsReset = (Get-MpPreference).EnableControlledFolderAccess
    if ($doesCFANeedsReset) {
        LogAndConsole "[+] Turn off CFA temporarily for lnk repair"
        Set-MpPreference -EnableControlledFolderAccess 0
    }
}
catch {
    LogAndConsole "[!] Unable to control CFA temporarily for lnk repair, for best results please turn off Controlled Folder Access and try again!"
    $doesCFANeedsReset = $false
}

# attempt vss recovery for restoring lnk files
$VssRecoveredLnks = 0
if ($VssRecovery) {
    try {
        $VssRecoveredLnks = VssFileRecovery($events_time)
        LogAndConsole "[+] VSSRecovery found $VssRecoveredLnks lnks, Proceeding..."
    }
    catch {
        LogErrorAndConsole "[!] VSSRecovery failed!"
    }
}

# Check for shortcuts in Start Menu, if program is available and the shortcut isn't... Then recreate the shortcut
LogAndConsole "[+] Enumerating installed software under HKLM"
$hklm_apps_success, $hklm_apps_failures = LookupHKLMAppsFixLnks($programs)
LogAndConsole "`tFinished with $hklm_apps_failures failures and $hklm_apps_success successes in fixing Machine level app links"

LogAndConsole "[+] Enumerating installed software under HKU"
$hku_apps_success, $hku_apps_failures = LookupHKUAppsFixLnks($programs)
LogAndConsole "`tFinished with $hku_apps_failures failures and $hku_apps_success successes in fixing User level app links"

# Handle MpTaskBarRecover.exe cases
LogAndConsole "[+] Attempting TaskBar recovery for All Users using tool $TaskbarRecoveryToolName"
HandleMpTaskBarRecoverUtilRunOnce $MpTaskBarRecoverUtilDownload $false

# Trigger RunOnce for all logged on users
LogAndConsole "[+] Attempting to trigger RunOnce for currently all logged on users"
TriggerRunOnceForLoggedOnUsers

# Re-register RunOnce again
HandleMpTaskBarRecoverUtilRunOnce $MpTaskBarRecoverUtilDownload $true

if ($doesCFANeedsReset) {
    # turn it back on
    LogAndConsole "[+] Turn CFA back ON to its original state"
    Set-MpPreference -EnableControlledFolderAccess 1
    $doesCFANeedsReset = $false
}

#Saving the result
SaveResult -Succeeded -NumLinksFound $VssRecoveredLnks -HKLMAppsSuccess $hklm_apps_success -HKLMAppsFailure $hklm_apps_failures -HKUAppsSuccess $hku_apps_success -HKUAppsFailure $hku_apps_failures

# SIG # Begin signature block
# MIIlogYJKoZIhvcNAQcCoIIlkzCCJY8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCLq5Zcf3oyRZ2p
# 97jlqY2/9S5SQiSqY55MYNK8hmNaGKCCC14wggTrMIID06ADAgECAhMzAAAJaWnl
# VutOg/ZMAAAAAAlpMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIyMDUwNTIyMDAyN1oXDTIzMDUwNDIyMDAyN1owcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpucHUMbAq
# 9TX7bb9eT5HgeUEAkCQqx8db9IGteLWtjh7NXNnUoxW79fDID+6GZihupXDFRFP7
# pD+iewhd91gfBNLczlB1hMeaggJ988VzxWpMNgQ3fYpeJDEwMdhmExRJyZEIKYFH
# Dy/Bh5eykRIQmbiUi/r9+kj0W9hCMnuKRn2aXLee2YONt75g9vHH83+K+spbd04Y
# ECV7o416V9cN/T5Sff4V8Bfx3q5B4wS8eWrTYV2CYwUFJaK4RSyuPIbBwxRuZ4Fk
# uhonXnXHkaqQeMnd8PiFLppsga9wBhCDgmfamObmxwzl7gnl6jy0sNc7/3qMeWa2
# F/UKhk8suiwNAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUP5G9CxyPFlyBsy62z8QNx41WZv0wUAYDVR0RBEkw
# R6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MRYwFAYDVQQFEw0yMzAwMjgrNDcwMDM5MB8GA1UdIwQYMBaAFNFPqYoHCM70JBiY
# 5QD/89Z5HTe8MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNybDBX
# BggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljV2luUENBXzIwMTAtMDctMDYuY3J0MAwGA1UdEwEB
# /wQCMAAwDQYJKoZIhvcNAQELBQADggEBAB4ai/kHW6cL86Rj+whuX/0UERNcW/Ls
# KHite2ZfF46eYv73CyuLFzuCpc9Kuo41WjQx1Sl/pTeSPx57lJHQRmeVK+yYvm24
# 8LsVmLUiTZC1yRQ+PLvNfmwf26A3Bjv2eqi0xSKlRqYNcX1UWEJYBrxfyK+MWEtd
# 84bwd8dnflZcPd4xfGPCtR9FUuFVjf+yXrSPUnD3rxT9AcebzU2fdqMGYHODndNz
# ZmoroyIYPE7bIchKPa0WeQwT7pGf5FZdWCo/M8ym2qzIKhFGyG67cI5ZTErj4nvv
# s5NSLMP0Og+6TQ5mRgVCwZyRknQ/1qLuuZNDd0USoHmOVTtp8tqqOiAwggZrMIIE
# U6ADAgECAgphDGoZAAAAAAAEMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDYyMDQwMjNaFw0y
# NTA3MDYyMDUwMjNaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBDQSAyMDEwMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHm7OrHwD4S4rWQqdRZz0LsH9j4NnRTk
# sZ/ByJSwOHwf0DNV9bojZvUuKEhTxxaDuvVRrH6s4CZ/D3T8WZXcycai91JwWiwd
# lKsZv6+Vfa9moW+bYm5tS7wvNWzepGpjWl/78w1NYcwKfjHrbArQTZcP/X84RuaK
# x3NpdlVplkzk2PA067qxH84pfsRPnRMVqxMbclhiVmyKgaNkd5hGZSmdgxSlTAig
# g9cjH/Nf328sz9oW2A5yBCjYaz74E7F8ohd5T37cOuSdcCdrv9v8HscH2MC+C5Me
# KOBzbdJU6ShMv2tdn/9dMxI3lSVhNGpCy3ydOruIWeGjQm06UFtI0QIDAQABo4IB
# 4zCCAd8wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNFPqYoHCM70JBiY5QD/
# 89Z5HTe8MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGdBgNVHSAEgZUw
# gZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0
# HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0
# AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEALkGmhrUGb/CAhfo7yhfpyfrkOcKUcMNk
# lMPYVqaQjv7kmvRt9W+OU41aqPOu20Zsvn8dVFYbPB1xxFEVVH6/7qWVQjP9DZAk
# JOP53JbK/Lisv/TCOVa4u+1zsxfdfoZQI4tWJMq7ph2ahy8nheehtgqcDRuM8wBi
# QbpIdIeC/VDJ9IcpwwOqK98aKXnoEiSahu3QLtNAgfUHXzMGVF1AtfexYv1NSPdu
# QUdSHLsbwlc6qJlWk9TG3iaoYHWGu+xipvAdBEXfPqeE0VtEI2MlNndvrlvcItUU
# I2pBf9BCptvvJXsE49KWN2IGr/gbD46zOZq7ifU1BuWkW8OMnjdfU9GjN/2kT+gb
# Dmt25LiPsMLq/XX3LEG3nKPhHgX+l5LLf1kDbahOjU6AF9TVcvZW5EifoyO6BqDA
# jtGIT5Mg8nBf2GtyoyBJ/HcMXcXH4QIPOEIQDtsCrpo3HVCAKR6kp9nGmiVV/UDK
# rWQQ6DH5ElR5GvIO2NarHjP+AucmbWFJj/Elwot0md/5kxqQHO7dlDMOQlDbf1D4
# n2KC7KaCFnxmvOyZsMFYXaiwmmEUkdGZL0nkPoGZ1ubvyuP9Pu7sCYYDBw0bDXzr
# 9FrJlc+HEgpd7MUCks0FmXLKffEqEBg45DGjKLTmTMVSo5xqx33AcQkEDXDeAj+H
# 7lah7Ou1TIUxghmaMIIZlgIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACWlp5VbrToP2TAAAAAAJaTANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgzYKMleQovu+ylBs+E7ODIhbI2AB/ilgjhDvrzrRh
# G5YwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQDTZyreDknB
# MMDGtH0ZVvScf7na2zzFK/z66kdMEf0bqaG/wp5vVlY35y0+Sc5WUjUYdDCIOzLE
# yhEUREq1yQEepNjrNWYGww3yscyZJg7AzL5+OD3DDyKWN833qM2qU3vYdN4gCaNu
# lhWZXsW3Y8JGua2JInue/imH0RNw1//qKa+ielaFkG6xPDLWac3UU3lHGa1E+2py
# Lsnk2jQFpdmqNkdBqw8UEJ5boEOWcoXbTjGkP+s32kKwyw+jmBLifn4cz/lt8O0o
# KRkwwrtrb7k4r7S+smqzwdubFVuSp0Z6FmQzo5oy50vTIh2yS8I5MpiuiUH8vXmi
# bzuA22ZWo6mzoYIXKTCCFyUGCisGAQQBgjcDAwExghcVMIIXEQYJKoZIhvcNAQcC
# oIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIB
# SASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIFf8Q7AZ
# 9/YRI/mcaIJwYGPiksfKVKNIXP3ols5Sd/W6AgZjx9zKiawYEzIwMjMwMTIxMDQx
# NTA0LjA3NlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0LUQy
# MjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghF4MIIH
# JzCCBQ+gAwIBAgITMwAAAbn2AA1lVE+8AwABAAABuTANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMjA5MjAyMDIyMTdaFw0y
# MzEyMTQyMDIyMTdaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJENC1EMjIwMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA40k+yWH1FsfJAQJtQgg3EwXm5CTI3TtUhKEhNe5s
# ulacA2AEIu8JwmXuj/Ycc5GexFyZIg0n+pyUCYsis6OdietuhwCeLGIwRcL5rWxn
# zirFha0RVjtVjDQsJzNj7zpT/yyGDGqxp7MqlauI85ylXVKHxKw7F/fTI7uO+V38
# gEDdPqUczalP8dGNaT+v27LHRDhq3HSaQtVhL3Lnn+hOUosTTSHv3ZL6Zpp0B3Ld
# WBPB6LCgQ5cPvznC/eH5/Af/BNC0L2WEDGEw7in44/3zzxbGRuXoGpFZe53nhFPO
# qnZWv7J6fVDUDq6bIwHterSychgbkHUBxzhSAmU9D9mIySqDFA0UJZC/PQb2guBI
# 8PwrLQCRfbY9wM5ug+41PhFx5Y9fRRVlSxf0hSCztAXjUeJBLAR444cbKt9B2ZKy
# UBOtuYf/XwzlCuxMzkkg2Ny30bjbGo3xUX1nxY6IYyM1u+WlwSabKxiXlDKGsQOg
# WdBNTtsWsPclfR8h+7WxstZ4GpfBunhnzIAJO2mErZVvM6+Li9zREKZE3O9hBDY+
# Nns1pNcTga7e+CAAn6u3NRMB8mi285KpwyA3AtlrVj4RP+VvRXKOtjAW4e2DRBbJ
# CM/nfnQtOm/TzqnJVSHgDfD86zmFMYVmAV7lsLIyeljT0zTI90dpD/nqhhSxIhzI
# rJUCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBS3sDhx21hDmgmMTVmqtKienjVEUjAf
# BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQ
# hk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBe
# MFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Nl
# cnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQE
# AwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAzdxns0VQdEywsrOOXusk8iS/ugn6z2SS
# 63SFmJ/1ZK3rRLNgZQunXOZ0+pz7Dx4dOSGpfQYoKnZNOpLMFcGHAc6bz6nqFTE2
# UN7AYxlSiz3nZpNduUBPc4oGd9UEtDJRq+tKO4kZkBbfRw1jeuNUNSUYP5XKBAfJ
# JoNq+IlBsrr/p9C9RQWioiTeV0Z+OcC2d5uxWWqHpZZqZVzkBl2lZHWNLM3+jEpi
# pzUEbhLHGU+1x+sB0HP9xThvFVeoAB/TY1mxy8k2lGc4At/mRWjYe6klcKyT1PM/
# k81baxNLdObCEhCY/GvQTRSo6iNSsElQ6FshMDFydJr8gyW4vUddG0tBkj7GzZ5G
# 2485SwpRbvX/Vh6qxgIscu+7zZx4NVBC8/sYcQSSnaQSOKh9uNgSsGjaIIRrHF5f
# hn0e8CADgyxCRufp7gQVB/Xew/4qfdeAwi8luosl4VxCNr5JR45e7lx+TF7QbNM2
# iN3IjDNoeWE5+VVFk2vF57cH7JnB3ckcMi+/vW5Ij9IjPO31xTYbIdBWrEFKtG0p
# bpbxXDvOlW+hWwi/eWPGD7s2IZKVdfWzvNsE0MxSP06fM6Ucr/eas5TxgS5F/pHB
# qRblQJ4ZqbLkyIq7Zi7IqIYEK/g4aE+y017sAuQQ6HwFfXa3ie25i76DD0vrII9j
# SNZhpC3MA/0wggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqG
# SIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
# MjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4X
# YDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTz
# xXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7
# uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlw
# aQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedG
# bsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXN
# xF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03
# dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9
# ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5
# UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReT
# wDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZ
# MBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8
# RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAE
# VTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAww
# CgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQD
# AgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb
# 186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29t
# L3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoG
# CCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9
# MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2Lpyp
# glYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OO
# PcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8
# DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA
# 0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1Rt
# nWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjc
# ZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq7
# 7EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJ
# C4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328
# y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC
# 1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJENC1EMjIw
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYF
# Kw4DAhoDFQDHYh4YeGTnwxCTPNJaScZwuN+BOqCBgzCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA53Wm9jAiGA8yMDIz
# MDEyMTA3NDkxMFoYDzIwMjMwMTIyMDc0OTEwWjB0MDoGCisGAQQBhFkKBAExLDAq
# MAoCBQDndab2AgEAMAcCAQACAgDtMAcCAQACAhFNMAoCBQDndvh2AgEAMDYGCisG
# AQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMB
# hqAwDQYJKoZIhvcNAQEFBQADgYEAv0EQmkPRTbVjSUjkaoyw6xxm70u/ygT/PqAt
# Lij1k4oeMUO+Eqky19wNnfa/72AYOPaHAyQmNNfE0tTrnhiWew3FJOVAGI540528
# Ofs/U3lXq9IqfDYxcKZKeyHn9ptfqsLEuiJ6jMseGHcJ29Jibp/Qn/d+LssO573V
# lAsg3n8xggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MAITMwAAAbn2AA1lVE+8AwABAAABuTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCNZj40dRoi8ukv
# ybLZ0Ljw+WEZ3IB3JDohH50SMUVnwjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQw
# gb0EIGTrRs7xbzm5MB8lUQ7e9fZotpAVyBwal3Cw6iL5+g/0MIGYMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG59gANZVRPvAMAAQAAAbkw
# IgQgUAHt82x2jzJrbn5FjxvgCCmMurbMW3gx/9hbgO7PI+8wDQYJKoZIhvcNAQEL
# BQAEggIApMtY/WQaVG4N8R1lHB+A/RLaxCWIdXY0xDs5n1wF3kQRKFHe/4BxROOR
# mIiwIgLwiO6XJAH4mZtrSO73Rr1lYgeJHF/KMrBgLGXuTs6DMcQexaX75+QAM06W
# 0eNninnjNcfu28MHNfHGfHtrwgi2QSZH9HegKldNF6t1Z5Xm6nbEKT3ZMTnG4JDM
# VyUMVdWMQ9mMVR+GMNWsqICTLFRQ7AhvairIXY+qTn2rBKwAbPVao/ZbkgFM1u6a
# 8IVUXlN3abAt0il5wBCUXPMDpwS8edx8XMq9ManT0sjNtCALDjIpzyUOak6J5Rdn
# 8onbIwEC6vSz3Ypp56w2L8sgj9brT7/XlDT5FYL1PYj9VeoCgfsC47DwogqqYl1j
# 2aSyfAuudvF+GDsJ0/WXKAlPPwzc+Q7qd/WjV7DR+6YuPq17em18Ns4yr0rcZMPX
# OaXwV+Zxhd8Vl/fescwtdWUOAKO4HmVQQ2LZhFIIYRgBlOc+RpREcnV/5GtKzxqs
# OOIXSsufLEXMbrfjUS9PuL7ja4wOCf7QQ1gQc0+ankpmjrCTyRTsftEL0458nDS6
# vm23Utj0ua3mLdFrAhMBReSZm9340l/PZQzW3pEdj8WU9Wff2o+8sn6JQqqnAWzh
# 1u3y6/CdjNpqDp0rrRNRqN3Vw9ODovPNYbuhxd9lJRCIsoyBDYg=
# SIG # End signature block
