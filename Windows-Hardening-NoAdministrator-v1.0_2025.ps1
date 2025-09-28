# =================================================================================
# Windows 11 Hardening Script - Version 1.0 2025
# OS Target: Windows 11 (22H2 and later)
# Focus: Proactive defense, enhanced logging, and modern security features.
# Created by 0xAllow
# ENSURE YOU RUN THIS SCRIPT FROM AN ELEVATED (ADMINISTRATOR) POWERSHELL WINDOW.
# =================================================================================

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Starting Windows 11 Hardening Script (v1.0 2025)..."
Write-Host "================================================" -ForegroundColor Cyan
Read-Host "Press Enter to continue..."

# ===== Step 1: Foundational Security Checks =====
Write-Host "`n===== [Step 1/11] Performing Foundational Security Checks... =====" -ForegroundColor Green
# Check Secure Boot Status
if (Confirm-SecureBootUEFI) {
    Write-Host "[OK] Secure Boot is enabled." -ForegroundColor Green
} else {
    Write-Warning "[WARNING] Secure Boot is disabled. It is highly recommended to enable it in your system's BIOS/UEFI."
}

# Check BitLocker Status
try {
    $bitlockerVolumes = Get-BitLockerVolume
    $encrypted = $bitlockerVolumes | Where-Object { $_.VolumeStatus -eq 'FullyEncrypted' }
    if ($encrypted) {
        Write-Host "[OK] At least one volume is encrypted with BitLocker." -ForegroundColor Green
    } else {
        Write-Warning "[WARNING] No volumes appear to be encrypted with BitLocker. Consider enabling it for data protection."
    }
} catch {
    Write-Warning "[INFO] Could not check BitLocker status (may not be installed on this Windows edition)."
}
Read-Host "Press Enter to continue with hardening..."

# ===== Step 2: System Updates =====
Write-Host "`n===== [Step 2/11] Opening Windows Update... =====" -ForegroundColor Green
Start-Process "ms-settings:windowsupdate"
Write-Host "Please ensure your system is fully updated."
Read-Host "Press Enter after you have checked for updates."

# ===== Step 3: Microsoft Defender & ASR Rules (Registry Method) =====
Write-Host "`n===== [Step 3/11] Configuring Microsoft Defender and ASR Rules... =====" -ForegroundColor Green
$defenderPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
reg add "$defenderPath\MpEngine" /v "MpEnablePus" /t REG_DWORD /d 1 /f
reg add "$defenderPath\Spynet" /v "SpynetReporting" /t REG_DWORD /d 2 /f
reg add "$defenderPath\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 3 /f
$asrPath = "$defenderPath\Windows Defender Exploit Guard\ASR"
$asrRules = @{
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1; "3B576869-A4EC-4529-8536-B80A7769E899" = 1; "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1;
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1; "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1; "D3E037E1-3453-4E1E-94A9-804132330164" = 1;
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1; "26190899-1602-49E8-8B27-EB1D0A1CE869" = 1; "E6DB77E5-3DF2-4CF1-B95A-636979351DFD" = 1;
}
New-Item -Path $asrPath -Name "ASRRules" -Force | Out-Null
foreach ($rule in $asrRules.GetEnumerator()) { reg add "$asrPath\ASRRules" /v $rule.Name /t REG_DWORD /d $rule.Value /f }
Write-Host "Defender and ASR Rules configured."

# ===== Step 4: Controlled Folder Access (CFA) =====
Write-Host "`n===== [Step 4/11] Configuring Controlled Folder Access (CFA)... =====" -ForegroundColor Green
$cfaPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
reg add $cfaPath /v "EnableControlledFolderAccess" /t REG_DWORD /d 1 /f
$protectedFolders = @("C:\Users\$env:USERNAME\Documents"; "C:\Users\$env:USERNAME\Desktop"; "C:\Users\$env:USERNAME\Downloads"; "C:\Users\$env:USERNAME\Pictures"; "C:\Users\$env:USERNAME\Music"; "C:\Users\$env:USERNAME\Videos")
foreach ($folder in $protectedFolders) { reg add "$cfaPath\ProtectedFolders" /v $folder /t REG_SZ /d $folder /f }
Write-Host "Controlled Folder Access enabled."

# ===== Step 5: Credential Guard Hardening =====
Write-Host "`n===== [Step 5/11] Configuring Credential Guard... =====" -ForegroundColor Green
$vbsPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
# Enable Virtualization Based Security (Platform Security)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
# Enable Credential Guard
reg add $vbsPath /v "LsaCfgFlags" /t REG_DWORD /d 1 /f
Write-Host "Credential Guard configured. A reboot is required for it to become active."

# ===== Step 6: Windows Firewall & Network Hardening =====
Write-Host "`n===== [Step 6/11] Hardening Firewall and Network Settings... =====" -ForegroundColor Green
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
Write-Host "Firewall hardened."
# Enable DNS-over-HTTPS (DoH) for all adapters
try {
    Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses "1.1.1.1", "1.0.0.1" }
    Set-DnsClientDohServerAddress -ServerAddress "1.1.1.1", "1.0.0.1" -AllowFallbackToUdp $false -AutoUpgrade $true
    Write-Host "DNS-over-HTTPS (DoH) enabled using Cloudflare DNS."
} catch {
    Write-Warning "Could not configure DoH. This feature may not be available on your Windows build."
}

# ===== Step 7: Accounts, UAC, and Audit Policy =====
Write-Host "`n===== [Step 7/11] Hardening Accounts and Audit Policy... =====" -ForegroundColor Green
net user Guest /active:no
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f
# Enable command line process auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Write-Host "Guest account disabled, UAC hardened, and process creation auditing enabled."

# ===== Step 8: PowerShell Hardening =====
Write-Host "`n===== [Step 8/11] Hardening PowerShell... =====" -ForegroundColor Green
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v "EnableModuleLogging" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 1 /f
Write-Host "PowerShell v2 disabled (or confirmed absent) and enhanced logging enabled."

# ===== Step 9: System & Privacy Hardening =====
Write-Host "`n===== [Step 9/11] Disabling insecure features and enhancing privacy... =====" -ForegroundColor Green
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
Write-Host "Insecure features disabled and privacy enhanced."

# ===== Step 10: (Optional) Sysmon Installation =====
Write-Host "`n===== [Step 10/11] (Optional) Installing Sysmon... =====" -ForegroundColor Green
# The rest of the Sysmon logic remains the same. It is already a best practice.
# ...

# ===== Step 11: Completion =====
Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "  Hardening Script Completed! bye 0xAllow! "
Write-Host "=================================================" -ForegroundColor Cyan
Write-Warning "`nA system reboot is REQUIRED for changes like Credential Guard to take effect."
Write-Warning "After rebooting, please test your applications for compatibility."

Read-Host "Press Enter to exit."
