# ASR rule “Block Win32 API calls from Office macro” - FP issue Frequently Asked Questions (FAQ)

Last updated: Jan 15, 2023 

**Background**\
On January 13, 2023, after updating to security intelligence versions between 1.381.2134.0 and 1.381.2163.0, some Windows Security and Microsoft Defender for Endpoint customers may have experienced false positive detections for the Attack Surface Reduction (ASR) rule "Block Win32 API calls from Office macro". These detections resulted in deletion of files that matched the incorrect detection logic - primarily impacting Windows shortcut (.lnk) files.  

 The incorrect detection logic was fixed in security intelligence version 1.381.2164.0 (and newer). This updated version stops the issue from happening. Devices that have been impacted prior to the fix, require explicit mitigation of the files deletion.    

 There is no data loss for customers who did not configure to “block” mode the ASR rule “Block Win32 API calls from Office macro” or did not deploy security intelligence versions 1.381.2134.0, 1.381.2140.0, 1.381.2152, or 1.381.2163.0.  

Review the following frequently asked questions for additional information on the impact scope and recommended mitigation steps.  

1. **What is the timeframe of the incident?**\
    Time in UTC: Jan 13, 2023 10:00:00 -  Jan 13, 2023 15:53:00
>>

2. **What Windows OS versions were impacted?**\
All supported versions of Windows 10 and Windows 11. Non-Windows operating systems (Mac, Linux, Mobile) were not impacted.
>>

3. **What specific ASR rule caused the issue?**\
“Block Win32 API calls from Office macro” – when set to “block” mode.  [Learn more about ASR rule modes at Enable attack surface reduction rules]
(https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide)
>>

4. **What security intelligence versions were impacted by the issue?**\
Security intelligence versions 1.381.2134.0 to 1.381.2163.0
>>

5. **What specific devices were impacted?**\
Devices where ASR rule “Block Win32 API calls from Office macro” was configured to “block”.  See Q11 how to identify impacted devices.
>>

6. **Did the issue impact devices where the ASR rule in question was set to “audit”?**\
No, device with this specific ASR rule set to “audit” or not configured were not impacted by the data loss.
>>

7. **Was this issue also present in Cloud-delivered Protection service (formerly Microsoft Active Protection Service (MAPS)) dynamic signature?**\
No, CP (MAPS) service was not impacted, only in the security intelligence channel was impacted.
>>

8. **Which Defender security intelligence versions contain a fix for this issue?**\
Security intelligence version 1.381.2164.0 or newer contain the fix for this issue.
>>

9. **Is that safe to turn on the ASR rule into “block” mode for security intelligence versions newer than 1.381.2164.0?**\
Yes, it is safe to turn back on ASR rule for security intelligence version 1.381.2164.0 or newer.
>>

10. **What is end user experience on impacted devices?**
* Application shortcuts are removed, leading to inability to launch common and LOB applications via Start Menu / Taskbar / Desktop.  
* When such impaired shortcut is clicked, an end user is presented with an error dialog that the item cannot be open/ application cannot be found.  
* Application icons on Taskbar are replaced with a placeholder icon – indicating that the shortcut is no longer valid. 
* In File Explorer, impacted shortcut files may be removed.
* Initial reports indicate that file types other than .lnk can be impacted. So far, the top observed non .lnk file extensions are library-ms, temp, cs, ps1, and url. Support channels are actively monitored to assess any additional impact. 
>>

11.	**How can remote administrator determine what devices are impacted?**
* A5/E5: administrators with access to MDE Advanced Hunting can run the following AH queries to identify impacted devices: 

<table>
<tr>
<td> Scenario </td> <td> Query </td> <td> Github link  </td>
</tr>
<tr>
<td> Retrieve all block events from devices with the ASR rule in “Block” mode </td>
<td>


```
DeviceEvents 
| where Timestamp >= datetime(2023-01-13) 
| where ActionType contains "AsrOfficeMacroWin32ApiCallsBlocked" 
| extend JSON = parse_json(AdditionalFields) 
| extend isAudit = tostring(JSON.IsAudit) 
| where isAudit == "false" 
| summarize by Timestamp, DeviceName, DeviceId, FileName,
 FolderPath, ActionType, AdditionalFields 
| sort by Timestamp asc 
```


</td>

<td>

```
[Retrieve_all_ASR_Rules_block_events]
(https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_AdvancedHunting/Retrieve_all_ASR_Rules_block_events)

```

</td>
</tr>

<tr>
<td> Retrieve all “.lnk” block events from devices with the ASR rule in “Block” mode  </td>
<td>


```
DeviceEvents 
| where Timestamp > datetime(2023-01-13) 
| where ActionType contains "AsrOfficeMacroWin32ApiCallsBlocked" 
| where FileName contains endswith ".lnk" 
| extend JSON = parse_json(AdditionalFields) 
| extend isAudit = tostring(JSON.IsAudit) 
| where isAudit == "false" 
| summarize by Timestamp, DeviceId, FileName, FolderPath,
 ActionType, AdditionalFields, isAudit 
| sort by Timestamp asc 
```


</td>

</td>

<td>

```
[Retrieve_all_lnk_block_events]
(https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_AdvancedHunting/Retrieve_all_lnk_block_events)
```

</td>

</tr>
<tr>
<td> Retrieve all events from devices with the ASR rule in “block” & “audit” mode  </td>
<td>


```
DeviceEvents
| where Timestamp > datetime(2023-01-13) 
| where ActionType contains "AsrOfficeMacroWin32ApiCallsBlocked" 
| summarize by Timestamp, DeviceName, DeviceId, FileName, FolderPath,
 ActionType, AdditionalFields 
| sort by Timestamp asc 
```


</td>

</td>

<td>

```
 [Retrieve_all_block_audit_ASR_rules_events]
(https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_AdvancedHunting/Retrieve_all_block_audit_ASR_rules_events)
```

</td>
</tr>
<tr>
<td> Retrieve count of devices with the ASR rule in “block” & “audit” mode - when device count exceeds 10K </td>
<td>


```
DeviceEvents 
| where Timestamp >= datetime(2023-01-13) 
| where ActionType contains "AsrOfficeMacroWin32ApiCallsBlocked" 
| summarize deviceCount = dcount(DeviceId) 
| extend IsMoreThanTenThousand = iif(deviceCount> 10000, True, False) 
```


</td>
<td>

```
[Retrieve_count_of_devices_with_ASR_rule_in_block_&_audit]
(https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_AdvancedHunting/Retrieve_count_of_devices_with_ASR_rule_in_block_%26_audit)
```

</td>
</tr>
</table>


* A3/E3: Microsoft is exploring options for A3/E3/Defender for Business customers. 
>>

12.	**Steps to mitigate the issue on impacted devices**\
Impacted customers need to: 
    1) Ensure across full Windows estate security intelligence version 1.381.2164.0 or newer (see Q13)
    2) Restore Start menu links to the most common artifacts using Microsoft recommended steps (see bullets 14-18)
    3) Expand Microsoft guidance to include organization-specific line of business (LOB) applications
>>

13.	**How to update security intelligence version**\
Security updates management options are enumerated in [Manage how and where Microsoft Defender Antivirus receives updates] https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-protection-updates-microsoft-defender-antivirus?view=o365-worldwide. This documentation covers options like Microsoft Update (~Windows Update), WSUS, SUS (SCCM+WSUS), MMPC (https://aka.ms/wdsi), UNC share. 
>>

14.	**How to recover/reconstruct deleted links**\
       Deleted .lnk artifacts can be recovered/reconstructed either using a remote management solution or manually by the local device user. 
>>

15.	**How to recover deleted links using remote management tools**\
    To restore Start shortcuts, run following script on impacted devices.
https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_scripts/AddShortcuts.ps1
**Note: This script must be run in elevated mode (either admin or system).**

    To include additional programs into the script: edit the $program variable and add a new line with the name of the application .lnk and the executable. 

    * Intune: follow these steps to restore via Intune: https://aka.ms/RestoreShortcuts-Intune
    * SCCM: https://learn.microsoft.com/en-us/mem/configmgr/apps/deploy-use/deploy-applications
    * Group Policy Preference – https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11)#client-side-extensions-1
>>

16.	**How to recover/reconstruct deleted links manually**\
    To recreate Start Menu shortcuts manually, run repair for affected applications from Settings. Running repair will recreate deleted links.  The application repair is effective for productivity programs like Microsoft 365, Microsoft Edge, and Microsoft Visual Studio.

    To repair an application, an end user can follow these steps: 

    **Windows 10:**
    1. Select Start  > Settings  > Apps > Apps & features
    2. Select the app you want to fix.
    3. Select Modify link under the name of the app if it is available.
    4. A new page will launch and allow you to select repair. 

    **Windows 11:** 
    1. Type “Installed Apps” in the search bar.
    2. Click “Installed Apps”.
    3. Select the app you want to fix.
    4. Click on “…”
    5. Select Modify or Advanced Options if it is available.
    6. A new page will launch and allow you to select repair.
>
For **Office applications installed using Click-to-Run**, an end user can leverage Office Click-to-Run repair mechanism.  

Click-to-Run repair mechanism can be invoked in both user session and system session – depending upon how the original install was done. If the original installation was done using user session, then run the repair also in the user session.  

**In user context (interactive mode)**

Execute the following command from user session with elevated privileges. The user will see the progress and will be prompted to shutdown any running Office Apps to complete the repair action. 

     *%programfiles%\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe scenario=Repair RepairType=QuickRepair DisplayLevel=false*

**In system context (non-Interactive mode)**

Run the following command from system session. There will be no UI shown to the user and any running Office applications will be automatically shutdown to complete the repair action. 

    *%programfiles%\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe scenario=Repair RepairType=QuickRepair DisplayLevel=false forceappshutdown=true*
>>

17.	**What links (.lnk) are covered by Microsoft v1 restoration script?**\
    The following application shortcuts, taken from telemetry as the most commonly impacted applications, will be recreated on Start menu after running AddShortcutsV1.ps1 restoration script. Links will be added only for applications present on a device. 

    > "Adobe Acrobat"\
    > "Adobe Photoshop 2023"\
    > "Adobe Illustrator 2023"\
    > "Adobe Creative Cloud"\
    > "Firefox Private Browsing"\
    > "Firefox"\
    > "Google Chrome"\
    > "Microsoft Edge"\
    > "Notepad++"\
    > "Parallels Client"\
    > "Remote Desktop"\
    > "TeamViewer"\
    > "Royal TS6"\
    > "Elgato StreamDeck"\
    > "Visual Studio 2022"\
    > "Visual Studio Code"\
    > "Camtasia Studio"\
    > "Camtasia Recorder"\
    > "Jabra Direct"\
    > "7-Zip File Manager"\
    > "Access"\
    > "Excel"\
    > "OneDrive"\
    > "OneNote"\
    > "Outlook"\
    > "PowerPoint"\
    > "Project"\
    > "Publisher"\
    > "Visio"\
    > "Word"\
    > "PowerShell 7 (x64)"\
    > "SQL Server Management Studio"\
    > "Azure Data Studio"
>>

18.**Limitations of the restoration scripts**
* The script assumes that applications are installed in their default installation path.

* For applications not listed in the prior step (17), the Microsoft authored script can be customized to include organizational line of business (LOB) applications and any additional applications common in the organizational environment.

* The script specifically restores Start Menu shortcuts (.lnk files). It does not restore Taskbar / Desktop / File Explorer shortcuts.

* If any non .lnk files were impacted, the script will not restore those.  

* The script has to be modified for non-English Windows versions to account for localized application installation location.  
>

19.**How to gradually roll out security intelligence updates**\
As a safe deployment practice, organizations should consider gradual rollout of security intelligence updates. Review this documentation for detailed guidance on gradual rollout of security updates:
    [Manage the gradual rollout process for Microsoft Defender updates]
    (https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-gradual-rollout?view=o365-worldwide)
>

20.**Is there a rollback mechanism for ASR rules?**\
ASR rules deployment mechanism does not currently provide a rollback option. The fastest route to mitigate an ASR rule issue is to configure the problematic ASR rule to run in "audit" mode.
[Enable attack surface reduction rules]
(https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide)

To mitigate the current data loss issue, customers need to take additional actions to recover/reconstruct impacted files.  More information on recovery options can be found at https://aka.ms/asrfprecovery.
>

21.**What data is collected by Microsoft restoration script to measure the script effectiveness?**\
The Microsoft restoration script collects and stores in the Windows registry the following data to evaluate the script effectiveness: the version of the restoration script, when it was run, the effectiveness of various methods, and the error message that script received if it fails.  This information will be analyzed by Microsoft to help improve the effectiveness of the tool.   To opt out of saving this information, run the script with the –Telemetry=$false option. 
>

22.**How to sign a PowerShell script**\
If your organizational policy only allows running signed PowerShell scripts, reference the following article to sign your restoration scripts: 
[about Signing - PowerShell]
(https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-7.3)
>
