Simple Powershell Windows Hardening 2025 v1.0 by 0xAllow

# Windows 11 Hardening Script - 2025 Edition

This PowerShell script is designed to significantly improve the security posture of a standalone Windows 11 workstation. It automates the process of applying modern security best practices, enabling proactive defenses, enhancing system monitoring, and disabling insecure legacy components.

The philosophy of this script is based on the principles of "Zero Trust" and "Assume Breach," focusing not only on prevention but also on detection and response capabilities.

## Key Features

-   **Proactive Threat Defense**: Enables powerful features like **Credential Guard** to protect against credential theft (e.g., Mimikatz) and configures **Attack Surface Reduction (ASR)** rules to block common malware behaviors.
-   **Ransomware Protection**: Activates **Controlled Folder Access (CFA)** to prevent unauthorized applications from modifying your critical files.
-   **Enhanced Privacy & Network Security**: Configures **DNS-over-HTTPS (DoH)** using a privacy-focused DNS provider to encrypt DNS queries, preventing snooping on public networks.
-   **Advanced Auditing & Logging**: Enables crucial security logging for **Process Creation** and enhances **PowerShell logging** (Script Block & Module), providing vital data for threat hunting and incident response.
-   **System Integrity Checks**: Performs pre-run checks to verify if foundational security features like **Secure Boot** and **BitLocker** are active.
-   **Foundation Hardening**: Implements essential security configurations, including hardening the Windows Firewall, securing UAC, and disabling the Guest account.
-   **Legacy Component Removal**: Disables outdated and insecure protocols and features like **SMBv1** and **PowerShell v2**.

---

## ⚠️ Disclaimer

**This script makes significant changes to your system's configuration. Run it at your own risk.**

-   **BACKUP YOUR DATA**: Always create a full system backup or a system restore point before running this script.
-   **COMPATIBILITY**: Some settings (especially Controlled Folder Access and ASR rules) may block legitimate applications from functioning correctly. You may need to manually create exceptions in the Windows Security settings.
-   **TARGET AUDIENCE**: This script is intended for personal, standalone workstations. **Do not run it in a corporate or enterprise environment without extensive testing and approval.**
-   **REBOOT REQUIRED**: A system reboot is required for many of the changes (especially Credential Guard) to take full effect.

---

## Prerequisites

-   **Operating System**: Windows 11 (Version 22H2 or later is recommended).
-   **Permissions**: Must be run with Administrator privileges.
-   **Hardware (for full effectiveness)**:
    -   UEFI with Secure Boot enabled.
    -   TPM 2.0.
    -   Virtualization support (Intel VT-x/AMD-V) enabled in the BIOS/UEFI for Credential Guard.

---

## How to Use

1.  **Download the Script**:
    Save the `Windows-Hardening-NoAdministrator-v1.0_2025.ps1` script to your local machine.

2.  **Set the PowerShell Execution Policy**:
    If you have never run PowerShell scripts before, you need to set the execution policy once. Open PowerShell as Administrator and run:
    ```powershell
    Set-ExecutionPolicy RemoteSigned
    ```
    When prompted, press `Y` and Enter.

3.  **Run the Script**:
    Right-click the `Windows-Hardening-NoAdministrator-v1.0_2025.ps1` file and select **"Run with PowerShell"**. This will automatically launch it with the required administrator privileges.

4.  **Follow the On-Screen Prompts**:
    The script will guide you through the process, including performing initial checks and asking for confirmation.

---

## Detailed Hardening Actions

The script performs the following actions, grouped by steps:

1.  **Foundational Security Checks**: Verifies if Secure Boot and BitLocker are enabled and warns the user if they are not.
2.  **System Updates**: Opens the Windows Update settings to ensure the system is fully patched.
3.  **Microsoft Defender & ASR**: Configures Defender with stricter settings and enables key Attack Surface Reduction (ASR) rules to block malicious behaviors.
4.  **Controlled Folder Access (CFA)**: Enables CFA to protect user profile folders from ransomware.
5.  **Credential Guard**: Enables virtualization-based security to isolate and protect credentials stored in memory (`lsass.exe`).
6.  **Firewall & Network Hardening**: Enables the Windows Firewall for all profiles, blocks inbound connections by default, and configures DNS-over-HTTPS (DoH).
7.  **Accounts, UAC, & Auditing**: Disables the Guest account, hardens the UAC prompt, and enables command-line process creation auditing.
8.  **PowerShell Hardening**: Disables the insecure PowerShell v2 engine and enables advanced module and script block logging.
9.  **System & Privacy Hardening**: Disables the insecure SMBv1 protocol and turns off telemetry and advertising-related tracking.
10. **Sysmon Installation (Optional)**: Provides an option to install Sysmon with a community-standard configuration for advanced system monitoring.

---

## Post-Execution Steps

1.  **Reboot Your System**: This is **mandatory** for changes like Credential Guard to become active.
2.  **Test Your Applications**: Open your most-used applications (e.g., Office, Adobe, games, development tools) to ensure they function correctly.
3.  **Manage Exceptions**: If an application is blocked by Controlled Folder Access, you will receive a notification. Go to **Windows Security > Virus & threat protection > Ransomware protection > Allow an app through Controlled folder access** to add an exception.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
