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
Script to detect impact from ASR rule "Block Win32 API calls from Office macro".
For information about this tool, including data it stores to understand effectiveness, go to https://aka.ms/ASR_shortcuts_deletion_FAQ
#>

param ([int] $Verbose = 3)

$ScriptVersionStr = "v1.0"

$LogFileName = [string]::Format("ShortcutImpactDetection{0}.log", (Get-Random -Minimum 0 -Maximum 99))
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
    }
    else {
        [string]$PSVersionTable.PSVersion.Major + '.' + [string]$PSVersionTable.PSVersion.Minor + '.' + [string]$PSVersionTable.PSVersion.Build
    }
}

Function IsServerSKU {
    return ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 1)
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
    foreach ($version in $versions) {

        if ($installTime -eq $null) {
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
                LogAndConsole "[+] Impacted Defender Signature Intelligence version $foundVersion no longer present on machine"
                LogAndConsole "[+] $foundVersion was installed $installTime, but removed $removalTime"
            }
            return $installTime, $removalTime , $foundVersion
        }
        else {
            if ($Verbose -gt 2) {
                LogAndConsole "[+] Impacted Defender Signature Intelligence version $foundVersion detected! Please update to a build >= 1.381.2164.0 and run again."
            }
            return $null
        }
    }
    else {
        LogAndConsole "[+] No impacted Defender Signature Intelligence versions detected on machine"
        return $null
    }

}

# Main
LogAndConsole "[+] Starting ASR impact detection for 'Block Win32 API calls from Office macro' - Script version: $ScriptVersionStr"
LogAndConsole "`tPowerShell Version: $(Get-PSVersion)"

# Validate elevated privileges
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if (!($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -Or ($id.Name -like "NT AUTHORITY\SYSTEM"))) {
    LogErrorAndConsole "[!] Not running from an elevated context"
    throw "Please run this script from an elevated PowerShell as Admin or as System"
    exit
}

# Exit if server OS detected
if (IsServerSKU) {
    LogAndConsole "[+] Server OS detected. Machine not impacted. Exiting."
    exit
}

# Check if machine is impacted
$events_time = GetTimeRangeOfVersion
if (-Not (($null -ne $events_time))) {
    LogAndConsole "[+] Machine was not impacted by ASR rule. If repair is still needed, please consult https://aka.ms/ASR_shortcuts_deletion_FAQ"
    exit
}
else {
    LogAndConsole "[+] Impact detected! Please consult https://aka.ms/ASR_shortcuts_deletion_FAQ for remediation."
}

# SIG # Begin signature block
# MIIlhAYJKoZIhvcNAQcCoIIldTCCJXECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDLiWkKJfWrlJRm
# I3i44kjiw26vrEeiME/OH5KBRCIwd6CCC14wggTrMIID06ADAgECAhMzAAAJaWnl
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
# 7lah7Ou1TIUxghl8MIIZeAIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACWlp5VbrToP2TAAAAAAJaTANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQg5jrt5c/a8oOulFz9JD4ZxbD9sa3K0oWuZQZWQhqv
# GHwwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQAx7u+CLO3S
# Z0mcbhtOxRPh3x1W21nuWb7qiYjtjXw+J99UbsxFzm9Osl/vpHjTwV9n4+2yv00y
# ItmNCSDdcwo+7Sq+85TCr0K+++GA7mv+mOWFVojpMs5uXbtnuUppSWBFaoTYQMUS
# vBD8IsypGZck48EcKm9e2S+bFOBpk50UiAAIDVFajR2r0vNTCAun2ggRSuvX+iDE
# MS3iXKNLs6rRAjx7YztO68VyRGIxpkf7hsxon42SbQefx5Q36fO0B5AUc8GKXNNR
# GrcXy+JoQ/AK5kkqsDxjDs8GWfyiV5q/H1xcn6RhFsjSNGYlqLtGz0wyF4e+7i9L
# 5gM8HoB+77SFoYIXCzCCFwcGCisGAQQBgjcDAwExghb3MIIW8wYJKoZIhvcNAQcC
# oIIW5DCCFuACAQMxDzANBglghkgBZQMEAgEFADCCAVQGCyqGSIb3DQEJEAEEoIIB
# QwSCAT8wggE7AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEILxL2esB
# +5cqS1Ykm87Jr8N/2S58OyQ2VBkq9kZlFUZ8AgZjoaHUe80YEjIwMjMwMTE3MDE1
# NjU0LjkyWjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRv
# IFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjc4ODAtRTM5MC04MDE0MSUw
# IwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRXzCCBxAwggT4
# oAMCAQICEzMAAAGoVfBhqcwwGFwAAQAAAagwDQYJKoZIhvcNAQELBQAwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwMzAyMTg1MTIzWhcNMjMwNTEx
# MTg1MTIzWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEp
# MCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNV
# BAsTHVRoYWxlcyBUU1MgRVNOOjc4ODAtRTM5MC04MDE0MSUwIwYDVQQDExxNaWNy
# b3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAo9ptysAuJdfymPJelww3z0pO9yaUCIPDilT4d6NmGJtR6j8dTL4/
# 1XFaEJfuiB54o8nrvv4t5V090bmFO8YOBK6jfD4BybNxdnZAIZSBRF4tQpuauvTp
# sHTGG+1nCh6WHG0+SMkWxtMa1K35XsThUKM91ipBn+I3QCtdeaBsR9XILBL6Ha6i
# gGEzlRxs+iC2vlWmB3NtQzj+ta6mYVWM8HVqyff7C/toEIryP1BQmuhjjLWmZlJ/
# RK4YxZjtybZy+tt2bteV2WOpF0db4JAAHgSqI6qC6Z9H5pKmjlPvkobT6ewGSOUZ
# KxTUGLXmnis/zylmdKinvcZ6b0ZY7YZEvA/XlgScqxzPGEZj5nw0RrRDAwyJWWSx
# 09Tsnmor2DEBCM4nOohInOEjBBa0QuqAmgfCSpPF6beCtjsHsM7NBOdCkpagvQdZ
# H0qoi9oLuL1eU+/657z2P17t+YHieHWG6XMQnNfpExT1MckyVs7o6s/c00QolbyO
# KkKfLwfV+69K4V+4Hu374or2DZzY0q7kTNKzWco2q2Xgo7dTPJcta9NEM7gPk9VA
# 51rS2qNL8BahSvEoLlk+WQsT5g+xLkb4T9UKAJqCE/IFmwc0rvAeVJ//bq6Eucqn
# pdEAiuiIRiX/nJbSZKGO+cBE+vQYiVKbQqupLAKNHlyRZPWwpoRvzDcCAwEAAaOC
# ATYwggEyMB0GA1UdDgQWBBQ2x9vj4vhS62U2H8zGMaSPSQsi1TAfBgNVHSMEGDAW
# gBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0
# YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUF
# BzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jv
# c29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8E
# AjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQBxO4JL
# ZGqqZ/aY+vo5TJ2GZTH6bq+kQ+zNaKglduexFufLracX1hdMq5I1YfVAV/Jz/Y3d
# hMSniETxi2FgqAMz8dSFRERfdZPAax5i64N5LFZElYKisAcXWTBDMgqCtRzcb65X
# ACYb8QjUQtETEDh+3HQSGt/n1ombs6eCfSVNJKIpR64YD4zLqgKL9XwRPHP55uW9
# AA1qW0mAZ+mm5ZdhPiOKxAoRO+gmMG/nH4EDSgQW7uAZp4wORmOc7m91/od4qd4g
# uz1m/AhaSBhCLZl6jNvGCUbljATGiLF6TGtFMNnAyiQhjFeZxyxxDTFeaH4je+ju
# FX1kwpNr09rPmd7hxzw53DVP7rbiYHRZpb0cATWGiMHoJt+6d21X+PDGZ0qHXmmU
# lec3XIzs4v3bgeoCImKwdqek4QnhSb1veEVRcTa4Qkv1pi4iCSxVgirU/b2tHhfu
# XPe4QkfoI6SgTr5Rxq43olgWCE30jwlEFYCEdfgZAeWeCx1+1YsuINkzKeWBEJnO
# Rgjbg31zH4PfrtjByWo1joJm4CDPDLXa5FgVBqxgdgrWGnPJO24j8DYHxwb4czpf
# WN/Z324BHAfr6EuQ+23f/k0GUtek6XmJnJGUGLuINeRY1reO4Z8sAnchIPI2HvK7
# 4fjJBjJGz8xWsKRZQmz0SK8sqw0nYH8iM2tK1jCCB3EwggVZoAMCAQICEzMAAAAV
# xedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENl
# cnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkz
# MDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH
# 0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPP
# dzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlh
# AnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP
# 1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVV
# mG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakX
# W2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+
# Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9
# Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdj
# bwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S
# 2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57
# t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEE
# AYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJd
# g/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYB
# BQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBv
# c2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4K
# AFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSME
# GDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRw
# Oi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJB
# dXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8y
# MDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvh
# nnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGU
# GCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZ
# GN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFd
# PSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7
# bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxy
# bxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJ
# VGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S
# 0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGE
# vL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurw
# J0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2l
# BRDBcQZqELQdVTNYs6FwZvKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0
# IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# Ojc4ODAtRTM5MC04MDE0MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBsuvzEn0EHisvhiDnxfUtnmJB3LKCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA53BhKzAiGA8yMDIzMDExNzAzNTAwM1oYDzIwMjMwMTE4MDM1MDAzWjB3MD0G
# CisGAQQBhFkKBAExLzAtMAoCBQDncGErAgEAMAoCAQACAgDRAgH/MAcCAQACAhNM
# MAoCBQDncbKrAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAqNpDwt8bKF7a
# dM1y9UyUesu/MbUvO9Gal8XSkMqX6cB0kHba+HDXzsOdaF7iu0+7WhQpGkYdi6fF
# 21bxteQuSBk4gVteIOK4B/IIaZTqJN+sImATyz6r7BXPRIg7YkmOeIDGKyvgb/oh
# LttfBGSeL51W9bmpHVZVu2KcYf1zbHYxggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAahV8GGpzDAYXAABAAABqDANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCAldr85bxXlmgCHCI2+WSqawuH1qluIxI3L6A1pTEYOODCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIHT+yx0AywfCc3CF8UFc+UWdG9aEepJf1gtT
# EEOXXGWmMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGoVfBhqcwwGFwAAQAAAagwIgQg9W4MkMaxZoOAbkal/IbQ9eKRamsgehrG1BIr
# m+AjCDQwDQYJKoZIhvcNAQELBQAEggIAXw6PFWDd5PUWxPxVSz87HmoyZIqZ/hk6
# dKqfXFY6XVcn/T3egHlxJNJeKIB+h3Qm0zl/FGpoCkkfol5XY3uyEzi2lp+A9zbD
# TwzRxV2zkH0fJhqahlKRrB9YP6zRdA9a8jFWztIufcnhR/7vs8cTX6vdbFQMOlTI
# 5cdyH3TRi9aV+8WOw4tL13CfXPzByqgcgC1oekrwlMRAhYLU1GvZAjx6u/scg2m5
# pzltoOfjXeNfFQsz4spNlIr6IHM59Ydbp3ouKnyA561sYEXTnR1TwDDQPlnRaZoy
# I+7bZ3KebAxLySdeK+4BbXI6t/oHPcKDBV0nYlBslLXtFBsmkftxUE2sDYAybUXh
# K5b3jvPkx7pI1TXOkzJmL5YJc3uwTwYxSHXBJajgt4vLStPbYYemH2fbRSd7faCv
# SdVGtb9ZjrL4fZ4kjeNdajYvARFbtTHOhA1U0n5JYqYP8aH4/fhvt7NyyLOYV8t+
# Hm0NRWhnp4hm3ZERHj0Dw8dFoosb/+gH7kseeYXZ+s6x0S74ocQlWIAgYncZNeoT
# y3Moy/6pQ1u2r1UEqKp1inZMFBnnnmYTbMV2cT2xdnu9Bs0tL5fX/Jg9z5mfHFzk
# Kaa5RfQysUuMD83AES1NjItpt9M/h2QGEMukLrZ2mtssntf+8JMkqKffpUUllbIQ
# w4lu2jqOOEQ=
# SIG # End signature block
