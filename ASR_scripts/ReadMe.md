# Block Win32 API calls from Office macro ASR Recovery Scripts

This repo contains sample PowerShell scripts, commands, and instructions to recover shortcuts (.lnk) impacted by the False Positive (FP) on Attack Surface Reduction rules (ASR Rules) - “Block Win32 API calls from Office macro” rule turned on in **block mode**. 

Please begin by reading the blog here: https://aka.ms/ASRFPRecovery

Then read the Frequently Asked Questions (FAQ) here: https://aka.ms/ASR_shortcuts_deletion_FAQ 

This repo contains information about the following scripts:
* AddShortcuts.ps1 - PowerShell script that attempts to restore impacted shortcuts based on information retrieved from VSS (shadow copy) and registry
* MpRecoverTaskbar.exe - Executable that attempts to restore taskbar links and libraries based on information retrieved from the registry

**_NOTE:_**  All of these scripts are signed by Microsoft

**_NOTE:_**  Please be aware of the following known limitations (all versions):
- Applications that have multiple paths (separated by a ;) in ``` SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths ``` are not currently supported.
- This script will create shortcuts in the Start Menu and not in a sub folder.  This may result in the creation of duplicate Start Menu items.  The script will not restore the items in a custom layout group.
- This script does not recreate links for UWP apps\WindowsApps
- This script may not recreate pinned Quick Launch or Start Menu items if they are not available in VSS.
- This script may not recreate links for Visual Studio (devenv.exe)


## AddShortCuts.ps1
This script provides a variety of techniques that can help recover links.
### Usage
```
AddShortcuts.ps1 [-Telemetry $false|$true ]  `
                 [ -ForceRepair ] `
                 [ -VssRecovery ] `
                 [ -MpTaskBarRecoverUtilDownload $false|$true ] `
                 [ -SkipBinaryValidation] `
                 [ -Verbose 0|1|2|3 ] `


Telemetry:                          Enable or disables having telemetry logging, default: true
ForceRepair:                        Repair is done irrespective of machine being considered affected or not, 
                                    default: true
VssRecovery:                        Use VSS recovery to restore lnk files, default: true
MpTaskBarRecoverUtilDownload:       Download the MpRecoverTaskbar.exe from the Microsoft Download Center, 
                                    default: true
                                    When this is false, the script assumes that MpRecoverTaskbar.exe resides in 
                                    the current working directory, default: true 
SkipBinaryValidation:               Skips validating the authenticity of MpRecoverTaskbar.exe whether download or 
                                    locally, default: false 
Verbose:                            Level of logging, default 1 
                                        0: No stdout and no log file
                                        1: Only stdout (default)
                                        2: both stdout and log file output
                                        3: detailed stdout along with log file output
```
### Fix links to software installed
The script iterates through ``` SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths ``` for both HKLM and HKU hives and looks for applications defined in the script. For those applications, a version is retrieved from the registry, and a shortcut is created in the appropriate Start Menu. This will run for all applications defined and in the registry, so customers may see new items added to the Start Menu.


### Adding additional applications
The script can be modified to include additional applications by adding an entry to the ```$programs``` variable.  

```
$programs = @{
    "Adobe Acrobat"                = "Acrobat.exe"
    "[Adobe Photoshop]"            = "photoshop.exe"
    "[Adobe Illustrator]"          = "illustrator.exe"
    ...
```
**Important:** ```$programs``` table is a key=value pair, with [] used to denote programs that have version year info, like [Visual Studio]. For such entries with [], we will lookup file description in file version info and use that, if it does not exist, we will fallback using generic name.

### Best effort to trigger RunOnce of MpRecoverTaskbar.exe 
The ```MpRecoverTaskbar.exe``` is a program that recovers taskbar data from the registry.  It needs to be run in user context, so the ```AddShortCuts.ps1``` simplifies this by adding it as a RunOnce to every user.  There is a best effort attempt to trigger RunOnce immediately for logged in users by impersonating their tokens.  This is only expected to work if the script is run from local SYSTEM account, and may work from an elevated administrator context depending on the local security policy.  Even if triggering the RunOnce is unsuccessful, then the .exe will run in the next time the user logs in.  Non logged on users will still have to log in to have the ```MpRecoverTaskbar.exe``` run.

The ```MpRecoverTaskbar.exe``` is either downloaded from the Microsoft Download Center or copied locally from the current working directory to the Windows directory.  Before copying the file to the Windows directory the script validates the authenticity of the binary, unless the SkipBinaryValidation is enabled.

### VSS Recovery (Optional)
If the script discovers VSS (shadow copy), then the shadow copies are mounted, and the following paths/extensions are restored if files exist

| Path | Extensions |
| ---- | ------     |
| \Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\ | .lnk |
| \ProgramData\Microsoft\Windows\Start Menu\ | .lnk |
| %USERPROFILE%\AppData\Roaming\Microsoft\Windows\ | .lnk |
| %USERPROFILE%\AppData\Roaming\Microsoft\Internet Explorer\ | .lnk |
| %USERPROFILE%\AppData\Roaming\Microsoft\Office\ | .lnk  |
| %USERPROFILE%\Favorites\ | .url |
| %USERPROFILE%\Desktop\ | .url |
| %USERPROFILE%\Desktop\ | .lnk |

### Saving Results (Optional) 
For information about this tool, including data it stores to understand effectiveness, go to https://aka.ms/ASR_shortcuts_deletion_FAQ

### Release History

| Version | Date    | Details | Link |
| ------- | ------- | ----------- | ------|
|  v5     | 01/20/2023 | <li>Improved error handling to ensure that RunOnce get run when a logged off user logs back in<li>||
|  v4     | 01/18/2023 | <li>```-ForceRepair``` is ```$true``` by default</li><li>Minor bug fixes</li> | https://aka.ms/ASRAddShortcuts |
|  v3     | 01/17/2023 |<li>Improved VSS recovery to restore .lnk files into Startup, Desktop, and Quick Launch.</li><li>Updated VSS recovery logic to look for shadow copies before '2023-01-13T06:04:45.000Z' on using the -ForceRepair option.</li><li>Enhanced support for localization - fixed bug where ACL didn't work outside of EN-US</li><li>Updated tool messages for better clarity & detail</li><li>Runs in User Context</li>   | https://aka.ms/ASRAddShortcutsv3 |
|  v2     | 01/16/2023 | <li>Volume Shadow Copy (VSS) Recovery is attempted by Default</li><li>Improvements to also recover Favorite URLs to Favorites & Desktop</li><li>Handling for Server SKU to skip the run as there was no impact</li><li>Better handling on non-english language systems</li>| https://aka.ms/ASRAddShortcutsv2 |
|  v1.1   | 01/15/2023 | <li>Added Volume Shadow Copy (VSS) Recovery switch</li><li>Added telemetry</li> |  https://aka.ms/ASRAddShortcutsV1.1 |
|  v1.0   | 01/14/2023 | <li>Recover shortcut in the “Start menu” from a static list</li> |  https://aka.ms/ASRAddShortcutsV1 |

### Notes
**#1:**  This script works best with PowerShell 5.x. The script has encountered issues with some versions of PowerShell 7.x. If you encounter an issue with PowerShell 7.x, please consider running this script with PowerShell 5.x.


## MpRecoverTaskbar.exe
Tool to try recovering taskbar shortcuts (.lnk) and library links.

- The tool restores Windows Library shortcuts for 6 known folders.
- The tool restores pinned taskbar shortcuts for win32 apps.
- Per profile pinned shortcuts are only supported for MsEdge and Chrome apps.

### Usage
```
CMD (non-admin)

MpRecoverTaskbar.exe [-v] [--notelemetry] [--force] [--forcerepair] [-?]

-v             verbose
--notelemetry  To disable telemetry reporting.
--forcerepair  Force repair shortcuts that are not pointing to right pinned targets.
--force        Force to rerun the tool on the same device.
-?             Display usage without running the tool.
```


### Release History
| Version |Date | Details | Microsoft Download Center Link |
|-----    |-----|------   |-----                           |
|   v2    | 01/17/2022 | <li>If you are using System Center Config Manager or Group Policy Object Editor or third-party tools then deploy both files and run the command “powershell -ep bypass -file .\AddShortcuts.ps1 -MpTaskBarRecoverUtilLocal” as Administrator.</li><li>The changes will come into effect after users logout and login to their accounts.</li><li>The MPRecoverTaskbar.exe can be run multiple times on end-user machines if necessary.  If end-users are missing taskbar icons after completing this process, then try running it a second time from %windir%\MPRecoverTaskbar.exe in the user context.</li><li>The name of the .exe is now MpRecoverTaskbar.exe. </li>|https://aka.ms/ASRTaskBarRepairTool|
|   v1   |  01/16/2022 | <li>Needs to run in user context (non-admin).</li><li>The name of the .exe is MpTaskBarRecovery.exe</li>| ?  |

### Notes
**#1:** Logs will be saved to ```%temp%\MpRecoverTaskBar-xxxx_x_x_x_x_x*.log``` 

# Deployment options
Here are a couple of deployment tools that can be used to push out the PowerShell script (AddShortcuts.ps1) and/or .exe's (MpRecoverTaskbar.exe).
* Intune (MEM, MDM) http://aka.ms/RestoreShortcuts-Intune
* System Center Configuration Manager (SCCM, MEMCM) https://aka.ms/RestoreShortcuts-SCCM

# How to check if your Windows 10 or Windows 11 machines are still running the impacted SIU:
In Advanced Hunting, you are able to run the following Advanced Hunting (AH) query to see if any of your devices require an updated version of the SIU: 
[Check what machines have the bad signatures](../ASR_AdvancedHunting/Check_what_machines_have_the_bad_signatures)

Once you confirm that the devices have an updated SIU, you can move the ASR Rules - “Block Win32 API calls from Office macro” rule to **block mode**.

# Suggestions and Feedback

We maintain a backlog of suggested sample PowerShell scripts in the project issues page. Feel free to comment, rate, or provide suggestions. We value your feedback. Let us know if you run into any problems or share your suggestions by adding an entry into the issues section.

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
