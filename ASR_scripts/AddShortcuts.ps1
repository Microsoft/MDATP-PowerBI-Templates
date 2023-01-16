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
# Credits: https://github.com/InsideTechnologiesSrl/DefenderBug/blob/main/W11-RestoreLinks.ps1
#           https://p0w3rsh3ll.wordpress.com/2014/06/21/mount-and-dismount-volume-shadow-copies/
#
         
Help:

Param Telemetry: enable or disable having telemetry logging, default: true
Param ForceRepair: repair is done irrespective of machine being considered affected or not, default: false
Param VssRecovery: Use VSS recovery to restore lnk files, default: false
Param Verbose: 
    Value 0: No stdout and no log file
    Value 1: Only stdout (default)
    Value 2: both stdout and log file output
    Value 3: detailed stdout along with log file output

#>

param ([bool] $Telemetry=$true, [switch] $ForceRepair=$false, [switch] $VssRecovery=$false, [int] $Verbose=1)

$ScriptVersionStr = "v1.1"

$programs = @{
    "Adobe Acrobat"                = "Acrobat.exe"
    "Adobe Photoshop 2023"         = "photoshop.exe"
    "Adobe Illustrator 2023"       = "illustrator.exe"
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
    "Royal TS6"                    = "royalts.exe"
    "Elgato StreamDeck"            = "StreamDeck.exe"
    "Visual Studio 2022"           = "devenv.exe"
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
    "PowerShell 7 (x64)"           = "pwsh.exe"
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
}

$LogFileName = [string]::Format("ShortcutRepairs{0}.log", (Get-Random -Minimum 0 -Maximum 99))
$LogFilePath = "$env:temp\$LogFileName";

Function Log {
    param($message);
    $currenttime = Get-Date -format u;
    $outputstring = "[" + $currenttime + "] " + $message;
    $outputstring | Out-File $LogFilepath -Append;
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
    } else {
        [string]$PSVersionTable.PSVersion.Major + '.' + [string]$PSVersionTable.PSVersion.Minor + '.' + [string]$PSVersionTable.PSVersion.Build
    }
}

# Saves the result of the script in the registry.  
# If you don't want this information to be saved use the -Telemetry $false option
Function SaveResult() {

    param(
        [parameter(ParameterSetName = "Failure")][switch][Alias("Failed")]$script_failed=$false,
        [parameter(ParameterSetName = "Failure")][string][Alias("ScriptError")]$script_error="Generic Error",
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("NumLinksFound")]$links_found=0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKUAppsSuccess")]$hku_success=0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKUAppsFailure")]$hku_failure=0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKLMAppsSuccess")]$hklm_success=0,
        [parameter(ParameterSetName = "Failure")][parameter(ParameterSetName = "Success")][int32][Alias("HKLMAppsFailure")]$hklm_failure=0,
        [parameter(ParameterSetName = "Success")][switch][Alias("Succeeded")]$script_succeeded=$false,
        [parameter(ParameterSetName = "Success")][parameter(ParameterSetName = "Failure")][Alias("User")][switch]$use_hkcu=$false
    )

    if ($use_hkcu) {
        $registry_hive = "HKCU:"     
    } else {
        $registry_hive = "HKLM:"
    }
    $registry_hive += "Software\Microsoft"
    $registry_name = "ASRFix"

    if ($Telemetry) {
         
        $registry_full_path = $registry_hive + "\" +$registry_name

        if (Test-Path -Path $registry_full_path) {
            #Registry Exists
        } else {
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
        } else {
            $result = "Failure"
            $script_result = 1
        }
 
        #Save the result in the registry
        New-ItemProperty -Path $registry_full_path -Name Version -Value 2 -Force | Out-Null 
        New-ItemProperty -Path $registry_full_path -Name ScriptResult -Value $script_result -Force -PropertyType DWORD | Out-Null
        New-ItemProperty -Path $registry_full_path -Name Timestamp -Value $timestamp -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name NumLinksFound -Value $links_found -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKUAppSuccess -Value $hku_success -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKUAppFailure -Value $hku_failure -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKLMSuccess -Value $hklm_success -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name HKLMFailure -Value $hklm_failure -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $registry_full_path -Name ScriptError -Value $script_error -Force | Out-Null

        if ($Verbose -ge 1) {
            LogAndConsole "Saved Result:  ScriptResult=$result ($script_result), TimeStamp=$timestamp, NumLinksFound=$links_found, HKUAppSuccess=$hku_success, HKUAppFailure=$hku_failure,  HKLMSuccess=$hklm_success, HKLMFailure=$hklm_failure,  ScriptError=$script_error in registry $registry_full_path"
        }
    }  
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
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
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
    } Catch {
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
        } else {
            $sPath = "$($_)\"
        }
        
        $tPath = Join-Path -Path $Destination -ChildPath (
        '{0}-{1}' -f (Split-Path -Path $sPath -Leaf),[GUID]::NewGuid().Guid
        )
         
        try {
            if (
                [mklink.symlink]::CreateSymbolicLink($tPath,$sPath,1)
            ) {
                LogAndConsole "Successfully mounted $sPath to $tPath"
                return $tPath
            } else  {
                LogAndConsole "Failed to mount $sPath"
            }
        } catch {
            LogAndConsole "Failed to mount $sPath because $($_.Exception.Message)"
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
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [Alias("FullName")]
    [string[]]$Path
)
Begin {
}
Process {
    $Path | ForEach-Object -Process {
        $sPath =  $_
        if (Test-Path -Path $sPath -PathType Container) {
            if ((Get-Item -Path $sPath).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                try {
                    [System.IO.Directory]::Delete($sPath,$false) | Out-Null
                    LogAndConsole "Successfully dismounted $sPath"
                } catch {
                    LogAndConsole "Failed to dismount $sPath because $($_.Exception.Message)"
                }
            } else {
                LogAndConsole "The path $sPath isn't a reparsepoint"
            }
        } else {
            LogAndConsole "The path $sPath isn't a directory"
        }
     }
}
End {}
}

#If there is any error, save the result as a failure
trap {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (!($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -Or ($id.Name -like "NT AUTHORITY\SYSTEM"))) {
        SaveResult -Failed -User -ScriptError $_
    } else {
        SaveResult -Failed -ScriptError $_
    }
    exit
}

Function GetTimeRangeOfVersion() {

  $versions =  "1.381.2140.0", "1.381.2152.0", "1.381.2160.0"

  $installTime = $null
  $removalTime = $null
  $foundVersion = $null

  foreach ($version in $versions) {
    if ($null -eq $installTime)
    {
        $lgp_events = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | where {$_.Id -eq 2000 -and $_.Properties[2].Value -like $version}
        if ($lgp_events)
        {
            $installTime =  @($lgp_events[0]).TimeCreated
            $foundVersion = $version
        }
    }
    $rgp_events = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | where {$_.Id -eq 2000 -and $_.Properties[3].Value -like $version}
   if ($rgp_events)
    {
        $removalTime =  @($rgp_events[0]).TimeCreated
    }
 }
 if ($installTime ) {
   if ($removalTime) {
      if ($Verbose -gt 2) {
        LogAndConsole "Install time $installTime, removal time $removalTime for build $foundVersion"
      }
      return $installTime, $removalTime , $foundVersion
   } else {
      if ($Verbose -gt 2) {
          LogAndConsole "Broken build version $foundVersion is still installed! First update to a build >= 1.381.2164.0 and run again."
      }
      return $null
   }
} else {
    LogAndConsole "[+] No Broken Builds installed on the machine"
   return $null
  }

}

Function GetShadowcopyBeforeUpdate( $targetDate ) {

    $shadowCopies = $null

    $shadowcopies =  Get-WmiObject Win32_shadowcopy | Where-Object { [System.Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate) -lt $targetDate } | Sort-Object InstallDate -Descending 

    $driveDict = @{}
    foreach ($shadow in $shadowcopies ) {
        LogAndConsole "$shadow.VolumeName $shadow.DeviceObject $shadow.InstallDate  $shadow.CreationTime"
        $escapedDrive = $shadow.VolumeName -replace '\\', '\\'
        $volume = Get-WmiObject -Class Win32_Volume -Namespace "root\cimv2" -Filter "DeviceID='$escapedDrive'"

        if ($null -eq $driveDict[$volume.DriveLetter]) {
            $driveDict[$volume.DriveLetter] = @()
        } 
        $driveDict[$volume.DriveLetter] += $shadow
    }
    
    return $driveDict
}

function getAllValidLNKsForDrive($path, $drive, $prefix) {
   $prefixLen = $($path).length
   
   LogAndConsole "Listing .lnk for $path\$($prefix)*"
   $lnkFiles = Get-ChildItem -ErrorAction SilentlyContinue -Path "$path\$($prefix)*" -Include "*.lnk" -Recurse -Force
   LogAndConsole "Now analyzing .lnk files..."
      
   if ($lnkFiles) {
      $validLinks = @()
      foreach ($lnkFile in $lnkFiles) {
         try {
            $target = (New-Object -ComObject WScript.Shell).CreateShortcut($lnkFile.FullName).TargetPath
            $targetFile = Get-Item -Path $target -ErrorAction Stop
            
         } catch {
            LogAndConsole "The target of $($lnkFile.FullName) does not exist. Skipped!"
         }
         LogAndConsole "Found LNK: $($lnkFile.FullName)"
         $drivePath = $drive + $lnkFile.FullName.Substring($prefixLen)
         try {
            LogAndConsole "Checking original: $($drivePath)"
            $originalLink = Get-Item -Path $drivePath -ErrorAction Stop
         } catch {
            LogAndConsole "Original path doesn't exist anymore: $($drivePath)"
            Copy-Item -Path $lnkFile.FullName -Destination $drivePath
            $validLinks += $lnkFile
         }
      }
      return $validLinks
   } else {
      LogAndConsole "No .lnk files were found in the shadow copy"
   }
}

Function VssFileRecovery($events_time) {
    LogAndConsole "[+] Starting vss file recovery"
    if ($events_time)
    {
        if ($Verbose -gt 2)
        {
            LogAndConsole ("`tStart time of update: $($events_time[0])")
            LogAndConsole ("`tEnd time of update: $($events_time[1])")
        }

        $shadowcopies = GetShadowcopyBeforeUpdate( $events_time[0])
        if ($shadowcopies) {
            $index = 0
            # create a directory for vss mount
            $guid = New-Guid
            $target =  "$env:SystemDrive\vssrecovery-$guid\"
            New-Item -Path $target -ItemType Directory -force | Out-Null
            foreach ($drive in $shadowCopies.Keys) {
                LogAndConsole "Restoring items for drive $drive"
                foreach ($shadowCopy in $shadowCopies[$drive]) {
                    LogAndConsole $($shadowCopy.DeviceObject)
                    $res = Mount-VolumeShadowCopy $shadowCopy.DeviceObject -Destination $target -Verbose
                
                    $lastNDays = -10        # Time range of days the user must have logged on to be included. e.g. within last 10 days
                
                    # get list of profiles that have been modified within range
                    $localUsersPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name ProfilesDirectory 
                    $profiles = Get-ChildItem -Path "$($localUsersPath)\*\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force  `
                                        | Select Directory, LastWriteTime  `
                                        | Where-Object {$_.LastWriteTime  -gt (Get-Date).AddDays($lastNDays)} 
                
                    foreach ($profilename in $profiles) {
                        $fullpath = $profilename.Directory.ToString()             # fullpath to usrclass.dat
                        $idx = $fullpath.IndexOf("\", $localUsersPath.Length + 1) # get C:\Users\<user> component
                        $profiledir = (Split-Path $fullpath.SubString(0,$idx) -NoQualifier).Trim("\")
                
                        LogAndConsole "Now enumerating for $($profiledir)"
                        $lnks  = getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Windows\"
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Internet Explorer\"
                        $lnks += getAllValidLNKsForDrive -path $res -drive $drive -prefix "$($profiledir)\AppData\Roaming\Microsoft\Office\"
                    }
                    Get-ChildItem -Path $target | Dismount-VolumeShadowCopy -Verbose
                    $index += 1
                }
            }
            if ($Verbose -gt 2) {
                LogAndConsole "`tRecovered Links from VSS: $($lnks)"
            }
            #remove vss directory
            Remove-Item -Path $target -Recurse -force | Out-Null
            return $index
        }
        else {
            LogErrorAndConsole ("[!] No shadow copy could be found before update, unable to do VSS recovery!")
        }
    }
}

Function CopyAclFromOwningDir($path, $SetAdminsOwner) {
    $base_path = Split-Path -Path $path
    $acl = Get-Acl $base_path
    if ($SetAdminsOwner){
        $group = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
	    $acl.SetOwner($group)
    }
    Set-Acl $path $acl
}

Function LookupHKLMAppsFixLnks($programslist)
{
    $success = 0
    $failures = 0
    $programslist.GetEnumerator() | ForEach-Object {
        $reg_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($_.Value)"
        try {
            $apppath = $null
            $target = $null
            try { $apppath = Get-ItemPropertyValue $reg_path -Name "Path" -ErrorAction SilentlyContinue } catch {}
            if ($null -ne $apppath)
            {
                if ($apppath.EndsWith(";") -eq $true){
                    $apppath = $apppath.Trim(";")
                }
                if ($apppath.EndsWith("\") -eq $false){
                    $apppath = $apppath + "\"
                }
                $target = $apppath + $_.Value
            }
            else
            {
                try { $target = Get-ItemPropertyValue $reg_path -Name "(default)" -ErrorAction SilentlyContinue } catch {}
            }
            if ($null -ne $target) {
                if (-not (Test-Path -Path "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\$($_.Key).lnk")) {
                    LogAndConsole ("`tShortcut for {0} not found in \Start Menu\, creating it now." -f $_.Key)
                    $target = $target.Trim("`"")
                    $shortcut_path = "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\$($_.Key).lnk"
                    $description = $_.Key
                    $workingdirectory = (Get-ChildItem $target).DirectoryName
                    $WshShell = New-Object -ComObject WScript.Shell
                    $Shortcut = $WshShell.CreateShortcut($shortcut_path)
                    $Shortcut.TargetPath = $target
                    $Shortcut.Description = $description
                    $shortcut.WorkingDirectory = $workingdirectory
                    $Shortcut.Save()
                    Start-Sleep -Seconds 1			# Let the LNK file be backed to disk
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

Function LookupHKUAppsFixLnks($programslist)
{
	$success = 0
    $failures = 0
	$guid = New-Guid
	New-PSDrive -PSProvider Registry -Name $guid -Root HKEY_USERS -Scope Global | Out-Null
	$users = Get-ChildItem -Path "${guid}:\"
	foreach ($user in $users){
		# Skip builtin    
		if ($user.Name.Contains(".DEFAULT") -or $user.Name.EndsWith("_Classes"))
		{        
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
			
            if ($null -ne $apppath)
            {
                if ($apppath.EndsWith(";") -eq $true){
                    $apppath = $apppath.Trim(";")
                }
                if ($apppath.EndsWith("\") -eq $false){
                    $apppath = $apppath + "\"
                }
                $target = $apppath + $_.Value
            }
			else
			{
				try { $target = Get-ItemPropertyValue Registry::$reg_path -Name "(default)" -ErrorAction SilentlyContinue } catch {}
			}
			
			if ($null -ne $target) {
				if (-not (Test-Path -Path "$profile_path\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($_.Key).lnk")) {
					LogAndConsole ("`tShortcut for {0} not found in \Start Menu\, creating it now." -f $_.Key)
					$target = $target.Trim("`"")
					$shortcut_path = "$profile_path\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($_.Key).lnk"
					$description = $_.Key
					$workingdirectory = (Get-ChildItem $target).DirectoryName
					$WshShell = New-Object -ComObject WScript.Shell
					$Shortcut = $WshShell.CreateShortcut($shortcut_path)
					$Shortcut.TargetPath = $target
					$Shortcut.Description = $description
					$shortcut.WorkingDirectory = $workingdirectory
					$Shortcut.Save()
					Start-Sleep -Seconds 1			# Let the LNK file be backed to disk
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

# Validate elevated privileges
LogAndConsole "[+] Starting LNK rescue - Script version: $ScriptVersionStr"
LogAndConsole "`tPowerShell Version: $(Get-PSVersion)"
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if (!($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -Or ($id.Name -like "NT AUTHORITY\SYSTEM"))) {
    LogErrorAndConsole "[!] Not running from an elevated context"
    throw "Please run this script from an elevated PowerShell as Admin or as System"
    exit
}

# Is Machine Affected Check, continue if $ForceRepair is true
$events_time = GetTimeRangeOfVersion
if (-Not ($ForceRepair -or ($null -ne $events_time))) {
    LogAndConsole "[+] Machine didnt get affected, if repair is still needed, please run script again with parameter -ForceRepair"
    exit
}
else {
    if ($ForceRepair) {
        LogAndConsole "[+] Continue repair honoring ForceRepair"
    }
}

# attempt vss recovery for restoring lnk files
$VssRecoveredLnks = 0
if ($VssRecovery) {
    try {
        $VssRecoveredLnks = VssFileRecovery($events_time)
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

#Saving the result
SaveResult -Succeeded -NumLinksFound $VssRecoveredLnks -HKLMAppsSuccess $hklm_apps_success -HKLMAppsFailure $hklm_apps_failures -HKUAppsSuccess $hku_apps_success -HKUAppsFailure $hku_apps_failure

