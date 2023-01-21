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

$ScriptVersion = 4
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

Function HandleMpTaskBarRecoverUtilRunOnce([bool]$download) {

    try {

        # Define the utility tool
        $util_path = "$env:windir\$TaskbarRecoveryToolName"

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
HandleMpTaskBarRecoverUtilRunOnce $MpTaskBarRecoverUtilDownload

if ($doesCFANeedsReset) {
    # turn it back on
    LogAndConsole "[+] Turn CFA back ON to its original state"
    Set-MpPreference -EnableControlledFolderAccess 1
    $doesCFANeedsReset = $false
}

#Saving the result
SaveResult -Succeeded -NumLinksFound $VssRecoveredLnks -HKLMAppsSuccess $hklm_apps_success -HKLMAppsFailure $hklm_apps_failures -HKUAppsSuccess $hku_apps_success -HKUAppsFailure $hku_apps_failures

# SIG # Begin signature block
# MIIleQYJKoZIhvcNAQcCoIIlajCCJWYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAYv8o75mfl74wy
# RB1SoXWsG7Wm3ZTalXi1YSBEFs/ClKCCC14wggTrMIID06ADAgECAhMzAAAJaWnl
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
# 7lah7Ou1TIUxghlxMIIZbQIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACWlp5VbrToP2TAAAAAAJaTANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgoklVfAa6xPEOxO+uMTRzBUBzWlrYv+eYO7YtjAcD
# GkMwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQBeQ7sTytWf
# e7jmAz1N5zPHwzciNwiECMn2l+qxzfsOBiLsT2QKu/olgmNVihfOXz+tYP/79vOx
# PqYNWgKEBDiu+Gvr9o3Vm8O7eHMvInWRTNhaXFtrgKi8L35FPjwZfxvXcFELh5yD
# TiLynzYu1A/JbJwKtszgph/oE3i2EAA4SP1F7JBdE9TZs1TrRr+5bBCMWM/0kDyV
# 0gTtWhlvrBgMDc9w3eC4n/g25mlGtdIohiG4T2Vmi3epiCfhZhyOLTmIgC3JWzLu
# QGek/TABLwOthhbXZXe8HedvCZV+S9s13+N6ZUjFDIWkJaZei8aemw3yDJY/6YOB
# ARn1rRpl6DcOoYIXADCCFvwGCisGAQQBgjcDAwExghbsMIIW6AYJKoZIhvcNAQcC
# oIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIB
# QASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEILpTctLN
# uqzIyF4jmIECX8+Uf8H9+eu848/JaVttmO+7AgZjv/CM08AYEzIwMjMwMTE5MDY0
# NDIzLjg4NFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ2QkQtRTNFNy0xNjg1MSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRVzCCBwwwggT0oAMC
# AQICEzMAAAHH+wCgSlvyJ9wAAQAAAccwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkwMTM1WhcNMjQwMjAyMTkw
# MTM1WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMG
# A1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046RDZCRC1FM0U3LTE2ODUxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQCvQtxW2dq00UwGtBO0b0/whIA/LIabE1+ETNo5WW3TzykFQUAhqyY3946KMTpR
# xp/dzZtWc3/TaKHSyZKpiSbk/dnBTtlbbTZvpw8MmNdyuMmPSp+e5xwG0TdZTS9n
# wKJAPuqsrF4XxgE1xL49W2+yqF3lhboDCFaqGPDWZi4t60Xlvpo+J//dHOXKobdJ
# XtA+JIl6d2zuAbjflGzLUcnheerO04lHjUjSPcRDTkkwXlA1GLuRPq9dNP4wdWPb
# sVVDtt5/9T7YQBsWPZfYA5Zu+CVhpiczeb8j85YMdSAbDwoh2wOHdbV66ycXYPuh
# 6caC1qGz5LUblSiV/kRKD/1n7fyuFDAuCiRjmTqnyTlqtha2zN0kromIhGXzjcfv
# iTv5CqVPYtsBA+ryK9C/SB1yVbZom6fUqtb6/nZHe8AcI61tSbG8PV40YeoaotqC
# 2Wr1QVcpe5eepcmqu4JiZ/B0UwPRQ/qKLWUV14ovzs92N0DDIKJVwISgue8PPK+M
# 2PG2RN3PpHjIXU39fg9JAfgWWCyXIEheCBpKU+28+7EC25pz8hOPiTQhFKEaJgsE
# zYPDqh6ws6jF7Ts5Q876pdc5wkxUeETQyWGGfF83YHUlYU9bBDqihaKoA5AOrNwP
# H7v2yHEDULHQrvR44GmUyiDbuBigukG/udHPi0eqhPK8DQIDAQABo4IBNjCCATIw
# HQYDVR0OBBYEFAVQ0t0cPsEAX9VT9f94QcuJRJIgMB8GA1UdIwQYMBaAFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBANDLlzyiA/TLzECw
# tVxrTvBbLWZP6epiAAWfPb3vaQ074onsATh/5JVu86eR5644+rfFz7pNLyDcW4op
# gTBiq+dEfFfny2OWxxmxl4qe7t8Y1SWk1P1s5AUdYAtRG6henxMseHGPc8Sr2PMV
# gE/Zg0wuiXvSiNjWqnN7ecwwl+l26t0EGlo4uUmZE1MuHF35EkYlBtjVcBzHqn8W
# KDCoFqxINTGn7TIU8QEH24ETcogsC2rp9zMangQx6ifpiaTIIYC1cwoMVBCB0/8h
# N7tWCEBVs9NWU/eFjV0WBz63xgrahsVIVUqyWQBIBMMe6UIyG35asiy6RyURQ/0N
# oyamrtLREs4MyJwjo+2qoY6F2dpGW0DR35Z/7S0+31JRW2s8nI7tYw8pvKQJFfOY
# crTrOvSSfViJRg1cKw6BocXkiY7ZnBDnhQTUjnmONR2V3KPL9Q8mDFGb03Jd47tp
# 1ivwrx/pDac8XS9aoUbt7DBoCXkKUp6vOyF+EHzO6NVHR3VFrtnTWWddiFa4+pVl
# rIWXskevqLqG6GlToFDr9WBjRwGKSxfiY0z4hJjzVPVFi3t9YBM27/OSMg1zOKnN
# t+DlL7d8ICjyBUHr7oDkvS8GDf12wUhO/oxYm5DxlnLt/CUUFkTh3kgVtG51qQ3A
# oZ3IsYzai1o2rvCbeS7vHjVQYCaQMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpENkJELUUzRTct
# MTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEB
# MAcGBSsOAwIaAxUA4gBI/QlJu/lHbfDFyJCK8fJyRiiggYMwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOdzAIgwIhgP
# MjAyMzAxMTkwNzM0MzJaGA8yMDIzMDEyMDA3MzQzMlowdzA9BgorBgEEAYRZCgQB
# MS8wLTAKAgUA53MAiAIBADAKAgEAAgIAiAIB/zAHAgEAAgISYjAKAgUA53RSCAIB
# ADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQow
# CAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBADTjSortmLi1a/LaRwlpvwnYuyiq
# 9ERmYFNWUQV8q8AcpT9rBKIUxrxN17ofQX12F2bu/bcbq16guW4s79yoNgNyV01Z
# ENcQRAGGzEb0C2VuK75oB+csc0dRw/7gk09rGwASiLlsnIP8zQzqDxujyN3wS42c
# UtM1ZYHok5Egrx1DMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAHH+wCgSlvyJ9wAAQAAAccwDQYJYIZIAWUDBAIBBQCgggFK
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg6gwH
# NJOJdB9hAAHVjUnqu4IRjm+jCSaJuNY3YgPppkMwgfoGCyqGSIb3DQEJEAIvMYHq
# MIHnMIHkMIG9BCBH5+Xb4lKyRQs55Vgtt4yCTsd0htESYCyPC1zLowmSyTCBmDCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABx/sAoEpb8ifc
# AAEAAAHHMCIEIN/6YSYBkhgW+Bpzt08sPFhPViOlFTFKbF8/o+4PsjYrMA0GCSqG
# SIb3DQEBCwUABIICAF7TujeO4rop+aYdkUzjDt9pDvKJBSPpqWLMDPZwkL3r7ynW
# zinRXaUal1uAYH9sK/ceeZAJTI9CWkzxVeoV1IPNoB9CfIbyY53aSVXYLdyROiwW
# 0I27gfZ6iYhfhHZo5K1IVzOAgPcqpAaWBp2kRbBvXYmhcUaRle3zx5FIPszDRkC4
# FPemIs9GmrHAvNXKAEJlD8vsGhD8NIahczhDVJuS7wZemYaI4l0yEUFSujMnPBO5
# XyO3W3wnJVvrYA8ywEM+a4Xe7Qsd4zOwzPUTSKll72+jDvr+QzhMWeUscHHsRr0O
# wyIpI6cGOCpomLe0Oki2V4pMzom3rlW+6BNpvPA58HKbLjSBXFuw1huPjwRAbn+Z
# k0sn1mUi5JfrX3UVDQWcMy3Ughjx0ap/WeBXh5WXRQWUUyTuEtsvClC3cZAxX2HD
# Ugga7dK3V0kcbF9aSXK1s0utsdvUuJ+rC4Pq2hUkOq4diLAFccUsW2KAzWlmWNc+
# Yp3UfUqOFWR8IkIUI6CJ0tj0FRjtrdiYwyA8sQVPdg8FI96pGhUlFQpDMUYGESdN
# zZxs7wnvDJ34tqJVuJx8iLlmZ62uwAKIoDDo7C5jlZhQ+o0UzmL0sIh9tinkKtZN
# X6M8ZVr5poDX0G4vfoRtd1xHdrgXpsXeMDfkhNb6F6SohJcZMDwuytsPv6+K
# SIG # End signature block
