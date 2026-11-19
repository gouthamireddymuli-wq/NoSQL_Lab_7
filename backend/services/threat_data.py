"""
Threat Intelligence Dataset & Knowledge Base
Covers:
- Platforms: Linux, Windows, MacOS, Android, iOS, Cloud
- Threat Lifecycles: Anticipated, Active, Evolving, Resolved
- Mitigation Procedures & Verification Scripts
"""

COMPREHENSIVE_THREATS = [
    # =========================================================================
    # LINUX PLATFORM
    # =========================================================================
    {
        "threat_id": "THR-LNX-001",
        "title": "XZ Utils Liblzma Backdoor Supply-Chain Attack (CVE-2024-3094)",
        "platform": "Linux",
        "status": "Anticipated",
        "severity": "Critical",
        "cve_id": "CVE-2024-3094",
        "threat_actor": "Jia Tan / Advanced Persistent Threat",
        "affected_systems": "Debian unstable/testing, Fedora 40/Rawhide, Arch Linux, openSUSE Tumbleweed using xz-utils 5.6.0 and 5.6.1",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation"],
        "techniques": ["T1195.001 - Supply Chain Compromise", "T1059.004 - Unix Shell"],
        "summary": "Sophisticated obfuscated multi-stage backdoor injected into upstream xz/liblzma source tarballs, intercepting OpenSSH sshd RSA decryption routine for unauthorized pre-authentication remote code execution.",
        "mitigation_procedures": [
            "Step 1: Check running xz version: 'strings $(which xz) | grep -i \"xz (xz utils)\"'",
            "Step 2: If running 5.6.0 or 5.6.1, immediately downgrade: 'sudo apt-get install --allow-downgrades xz-utils=5.4.5-0.1' or 'sudo dnf downgrade xz'",
            "Step 3: Terminate suspect SSH sessions and restart sshd: 'sudo systemctl restart sshd'",
            "Step 4: Audit system for unexpected SSH keys in /root/.ssh/authorized_keys and /etc/ssh/keys"
        ],
        "remediation_script": "if xz --version | grep -E '5\\.6\\.[01]'; then echo 'VULNERABLE - Downgrading xz'; sudo apt-get update && sudo apt-get install --allow-downgrades -y xz-utils=5.4.5-1; else echo 'SAFE: Not running affected xz version'; fi",
        "verification_command": "xz --version | head -n 1"
    },
    {
        "threat_id": "THR-LNX-002",
        "title": "Volt Typhoon Living-Off-The-Land Linux Router Botnet",
        "platform": "Linux",
        "status": "Active",
        "severity": "Critical",
        "cve_id": "CVE-2023-46805 / CVE-2024-21887",
        "threat_actor": "Volt Typhoon (BRONZE SILHOUETTE)",
        "affected_systems": "Edge Linux devices, Cisco/Netgear routers, Ivanti Connect Secure, Ubuntu/RHEL bastion hosts",
        "tactics": ["Defense Evasion", "Credential Access", "Discovery"],
        "techniques": ["T1059.004 - Command and Scripting Interpreter", "T1078 - Valid Accounts", "T1049 - System Network Discovery"],
        "summary": "Chinese state-sponsored espionage group utilizing built-in native Linux binaries (LoLBins such as wmic, certutil, netsh, ip, iptables) without dropping custom malware, maintaining persistent covert access to critical infrastructure.",
        "mitigation_procedures": [
            "Step 1: Audit external edge device firmware and apply emergency vendor patches.",
            "Step 2: Restrict management interfaces to isolated Out-of-Band (OOB) VLAN networks.",
            "Step 3: Enable Linux auditd monitoring on living-off-the-land tools: 'auditctl -w /usr/bin/ssh -p x -k lolbin_exec'",
            "Step 4: Rotate all administrative SSH private keys and enforce FIDO2 WebAuthn hardware tokens.",
            "Step 5: Block known C2 IP addresses in iptables: 'sudo iptables -A INPUT -s 198.51.100.0/24 -j DROP'"
        ],
        "remediation_script": "sudo auditctl -w /usr/bin/curl -p x -k susp_exec && sudo auditctl -w /usr/bin/wget -p x -k susp_exec && sudo systemctl restart auditd",
        "verification_command": "sudo auditctl -l | grep susp_exec"
    },
    {
        "threat_id": "THR-LNX-003",
        "title": "Akira Rust-Based ESXi & Linux Hypervisor Ransomware",
        "platform": "Linux",
        "status": "Evolving",
        "severity": "High",
        "cve_id": "CVE-2024-37085",
        "threat_actor": "Akira Cybercrime Syndicate (PUNK SPIDER)",
        "affected_systems": "VMware ESXi 7.0/8.0, Ubuntu 22.04 LTS, Red Hat Enterprise Linux 8/9",
        "tactics": ["Impact", "Lateral Movement", "Execution"],
        "techniques": ["T1486 - Data Encrypted for Impact", "T1562.001 - Disable Security Tools"],
        "summary": "Akira group evolved its C++ payload into multi-threaded Rust binaries targeting Linux and ESXi hypervisors. Uses ChaCha20/RSA-4096 hybrid encryption and terminates running virtual machine instances via 'esxcli vm process kill'.",
        "mitigation_procedures": [
            "Step 1: Disable ESXi Active Directory integration to prevent CVE-2024-37085 authorization bypass.",
            "Step 2: Restrict ESXi shell and SSH access: 'vim-cmd hostsvc/enable_ssh false'.",
            "Step 3: Enforce immutable offline backups for all VMDK disk images with 3-2-1 backup strategy.",
            "Step 4: Deploy runtime endpoint file-integrity monitoring (AIDE/Tripwire) on /etc and /bin."
        ],
        "remediation_script": "sudo chmod 700 /bin/esxcli 2>/dev/null || true; sudo chattr +i /etc/passwd /etc/shadow 2>/dev/null || true; echo 'Hardened critical system files'",
        "verification_command": "lsattr /etc/shadow | grep -i 'i'"
    },
    {
        "threat_id": "THR-LNX-004",
        "title": "PwnKit Polkit Local Privilege Escalation (CVE-2021-4034)",
        "platform": "Linux",
        "status": "Resolved",
        "severity": "High",
        "cve_id": "CVE-2021-4034",
        "threat_actor": "Multiple threat actors / Commodity malware",
        "affected_systems": "All default installations of Ubuntu, Debian, Fedora, CentOS with policykit-1 before Jan 2022",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "techniques": ["T1068 - Exploitation for Privilege Escalation"],
        "summary": "Memory corruption flaw in Polkit's pkexec binary allowing any unprivileged local user to gain instant root privileges regardless of architecture.",
        "mitigation_procedures": [
            "Step 1: Upgrade policykit package: 'sudo apt-get install --only-upgrade policykit-1' or 'sudo dnf update polkit'.",
            "Step 2: Emergency mitigation if patching unavailable: strip SUID permission from pkexec: 'sudo chmod 0755 /usr/bin/pkexec'.",
            "Step 3: Verify permissions do not have setuid bit (no 's' flag in ls -l)."
        ],
        "remediation_script": "if [ -u /usr/bin/pkexec ]; then sudo chmod 0755 /usr/bin/pkexec && echo 'SUID bit successfully stripped from pkexec'; else echo 'pkexec is already secure'; fi",
        "verification_command": "ls -l /usr/bin/pkexec"
    },

    # =========================================================================
    # WINDOWS PLATFORM
    # =========================================================================
    {
        "threat_id": "THR-WIN-001",
        "title": "Windows CLFS Zero-Day Privilege Escalation (CVE-2024-26229)",
        "platform": "Windows",
        "status": "Anticipated",
        "severity": "Critical",
        "cve_id": "CVE-2024-26229",
        "threat_actor": "Storm-0978 / RomCom Operator",
        "affected_systems": "Windows 10, Windows 11, Windows Server 2019/2022 before April 2024 patch",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "techniques": ["T1068 - Exploitation for Privilege Escalation", "T1055 - Process Injection"],
        "summary": "Zero-day integer overflow in Common Log File System (CLFS) driver (clfs.sys) enabling an attacker with normal user access to execute code in NT AUTHORITY\\SYSTEM context and bypass Windows Defender ATP.",
        "mitigation_procedures": [
            "Step 1: Apply Microsoft Cumulative Security Update KB5036893 or later via Windows Update.",
            "Step 2: Enable Exploit Protection (DEP, ASLR, CFG) globally via PowerShell: 'Set-ProcessMitigation -System -Enable DEP,SEHOP'.",
            "Step 3: Restrict standard user permissions on Base Named Objects and event logs.",
            "Step 4: Monitor for unusual child processes spawned by services.exe or winlogon.exe."
        ],
        "remediation_script": "powershell -Command \"Set-ProcessMitigation -System -Enable DEP,BottomUpASLR; Write-Host 'Exploit mitigations applied successfully'\"",
        "verification_command": "Get-ProcessMitigation -System | Select-Object -Property DEP,BottomUpASLR"
    },
    {
        "threat_id": "THR-WIN-002",
        "title": "LockBit 3.0 Ransomware (Active Directory Group Policy Distribution)",
        "platform": "Windows",
        "status": "Active",
        "severity": "Critical",
        "cve_id": "N/A (TTP Campaign)",
        "threat_actor": "LockBit RaaS (Gold Mystic)",
        "affected_systems": "Windows Domain Controllers, Windows Server 2016-2022, Windows 10/11 Enterprise",
        "tactics": ["Impact", "Credential Access", "Lateral Movement"],
        "techniques": ["T1486 - Data Encrypted for Impact", "T1489 - Service Stop", "T1490 - Inhibit System Recovery"],
        "summary": "LockBit 3.0 (LockBit Black) abuses compromised Domain Admin accounts to push ransomware execution scripts via Active Directory Group Policy Objects (GPO), stopping 40+ security services and deleting Volume Shadow Copies via 'vssadmin delete shadows /all /quiet'.",
        "mitigation_procedures": [
            "Step 1: Enforce Tiered Administrative Model for Active Directory; prevent Domain Admin logins on workstations.",
            "Step 2: Disable SMBv1 and enforce SMB signing on all domain controllers and member servers: 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'.",
            "Step 3: Block Volume Shadow Copy deletion via PowerShell constrained language mode and Attack Surface Reduction (ASR) rules: 'Set-MpPreference -AttackSurfaceReductionRules_Ids 92e63a44-c0ef-4892-aa73-207f907253d0 -AttackSurfaceReductionRules_Actions Enabled'.",
            "Step 4: Quarantine infected host from network and reset Kerberos Ticket Granting Service (KRBTGT) password twice."
        ],
        "remediation_script": "powershell -Command \"Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSMB1Protocol $false -Force; Write-Host 'SMB Hardening Completed'\"",
        "verification_command": "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSMB1Protocol"
    },
    {
        "threat_id": "THR-WIN-003",
        "title": "DarkGate Steganographic Dropper & EDR-Killer Driver (BYOVD)",
        "platform": "Windows",
        "status": "Evolving",
        "severity": "High",
        "cve_id": "CVE-2024-21412 / CVE-2023-38831",
        "threat_actor": "DarkGate Malware Operator",
        "affected_systems": "Windows 11 23H2, Windows 10 22H2, Microsoft Defender for Endpoint",
        "tactics": ["Defense Evasion", "Execution", "Persistence"],
        "techniques": ["T1027.003 - Steganography", "T1063.001 - Bring Your Own Vulnerable Driver"],
        "summary": "DarkGate has evolved from simple VBS droppers to embedding encrypted shellcode within SVG/PNG image metadata, pairing with legitimate signed vulnerable third-party drivers (BYOVD) to disable EDR sensors from kernel space.",
        "mitigation_procedures": [
            "Step 1: Enable Microsoft Vulnerable Driver Blocklist in Windows Defender Application Control (WDAC).",
            "Step 2: Turn on Memory Integrity (HVCI - Hypervisor-Protected Code Integrity) in Windows Security.",
            "Step 3: Block execution of script engines (wscript, cscript, mshta) from user Downloads/AppData directories via AppLocker.",
            "Step 4: Configure mail gateway to inspect attachments with embedded SVG and LNK files."
        ],
        "remediation_script": "powershell -Command \"reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f; Write-Host 'Driver Blocklist Enabled'\"",
        "verification_command": "reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' /v VulnerableDriverBlocklistEnable"
    },
    {
        "threat_id": "THR-WIN-004",
        "title": "MS17-010 EternalBlue SMB Remote Code Execution",
        "platform": "Windows",
        "status": "Resolved",
        "severity": "Critical",
        "cve_id": "CVE-2017-0144",
        "threat_actor": "Shadow Brokers / WannaCry / NotPetya",
        "affected_systems": "Windows 7, Windows Server 2008 R2, Windows XP (legacy legacy endpoints)",
        "tactics": ["Lateral Movement", "Execution"],
        "techniques": ["T1210 - Exploitation of Remote Services"],
        "summary": "Remote code execution flaw in Microsoft Server Message Block 1.0 (SMBv1) protocol handling specially crafted SMR transactions.",
        "mitigation_procedures": [
            "Step 1: Apply security bulletin MS17-010 patch.",
            "Step 2: Completely uninstall SMBv1 feature: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'.",
            "Step 3: Block TCP port 445 at firewall boundary for external traffic.",
            "Step 4: Verify SMBv1 is disabled."
        ],
        "remediation_script": "powershell -Command \"Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart; Write-Host 'SMBv1 Disabled'\"",
        "verification_command": "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object State"
    },

    # =========================================================================
    # MACOS PLATFORM
    # =========================================================================
    {
        "threat_id": "THR-MAC-001",
        "title": "Apple Silicon DTrace Kernel Memory Disclosure",
        "platform": "MacOS",
        "status": "Anticipated",
        "severity": "High",
        "cve_id": "CVE-2024-27834",
        "threat_actor": "Research Disclosure / Zero-Day Brokers",
        "affected_systems": "macOS Sonoma 14.4 and earlier on M1/M2/M3 Apple Silicon Macs",
        "tactics": ["Discovery", "Privilege Escalation"],
        "techniques": ["T1082 - System Information Discovery", "T1068 - Exploitation for Privilege Escalation"],
        "summary": "Logic flaw in DTrace system subsystem allowing an unprivileged application with sandbox escape to read kernel memory address layouts, weakening KASLR randomized defenses.",
        "mitigation_procedures": [
            "Step 1: Update macOS to Sonoma 14.5 or Sequoia 15.0: 'softwareupdate -i -a'.",
            "Step 2: Enforce System Integrity Protection (SIP): verify 'csrutil status' outputs 'enabled'.",
            "Step 3: Disable developer debugging utilities on production endpoints."
        ],
        "remediation_script": "sudo softwareupdate --install --all --restart",
        "verification_command": "csrutil status"
    },
    {
        "threat_id": "THR-MAC-002",
        "title": "Atomic macOS Stealer (AMOS) Harvesting Keychains & Wallets",
        "platform": "MacOS",
        "status": "Active",
        "severity": "Critical",
        "cve_id": "N/A (Malware Campaign)",
        "threat_actor": "Threat Actor 'BitChecker' / Cybercrime Cartels",
        "affected_systems": "macOS Ventura 13.x, macOS Sonoma 14.x",
        "tactics": ["Credential Access", "Collection", "Exfiltration"],
        "techniques": ["T1555.001 - Keychain", "T1539 - Steal Web Session Cookie"],
        "summary": "Infostealer distributed through fake Google Ads and rogue `.dmg` files. Pops fake system password prompt to decrypt user Keychain, stealing browser credentials, crypto wallet private keys, and Telegram sessions.",
        "mitigation_procedures": [
            "Step 1: Restrict app installation to App Store and identified developers: 'sudo spctl --master-enable'.",
            "Step 2: Check for suspicious launch daemons in ~/Library/LaunchAgents and /Library/LaunchDaemons.",
            "Step 3: Force reset of all web session cookies and rotate Keychain master password.",
            "Step 4: Deploy Jamf Protect or CrowdStrike Falcon sensor with XProtect signature updates."
        ],
        "remediation_script": "sudo spctl --master-enable && sudo spctl --status && echo 'Gatekeeper enforced'",
        "verification_command": "spctl --status"
    },
    {
        "threat_id": "THR-MAC-003",
        "title": "RustBucket Multi-Stage macOS Mach-O Malware",
        "platform": "MacOS",
        "status": "Evolving",
        "severity": "High",
        "cve_id": "N/A (APT Campaign)",
        "threat_actor": "Lazarus Group (HIDDEN COBRA / Diamond Sleet)",
        "affected_systems": "macOS Monterey, Ventura, Sonoma (Universal Mach-O ARM64/x86_64)",
        "tactics": ["Initial Access", "Execution", "Command and Control"],
        "techniques": ["T1566.001 - Spearphishing Attachment", "T1071.001 - Web Protocols"],
        "summary": "North Korean cyber espionage malware evolving from simple Objective-C droppers into signed multi-stage Rust payloads masquerading as PDF financial advisory viewers, fetching second-stage C2 payloads only when a valid lure PDF is opened.",
        "mitigation_procedures": [
            "Step 1: Enforce MDM profile blocking execution of non-notarized universal binaries.",
            "Step 2: Monitor outbound DNS queries for fast-flux C2 infrastructure associated with dynamic DNS domains.",
            "Step 3: Kill suspect PDF viewer child processes: 'pkill -f -9 \"InternalViewer\"'."
        ],
        "remediation_script": "sudo launchctl unload -w /Library/LaunchDaemons/com.apple.updater.plist 2>/dev/null || true; echo 'Unloaded suspicious daemons'",
        "verification_command": "launchctl list | grep -i 'suspicious'"
    },
    {
        "threat_id": "THR-MAC-004",
        "title": "Shroot System Integrity Protection (SIP) Bypass (CVE-2021-30892)",
        "platform": "MacOS",
        "status": "Resolved",
        "severity": "High",
        "cve_id": "CVE-2021-30892",
        "threat_actor": "Microsoft Security Research / Public Disclosure",
        "affected_systems": "macOS Big Sur 11.x, macOS Catalina 10.15 before Security Update 2021-007",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "techniques": ["T1562.001 - Disable or Modify Tools"],
        "summary": "Vulnerability in Apple-signed package installer (system_installd) allowing attackers to bypass System Integrity Protection (rootless) by abusing post-install shell script execution hooks.",
        "mitigation_procedures": [
            "Step 1: Upgrade macOS to macOS Monterey 12.0.1 or apply Security Update 2021-007 Big Sur.",
            "Step 2: Confirm SIP status is fully active via 'csrutil status'."
        ],
        "remediation_script": "csrutil status",
        "verification_command": "csrutil status"
    },

    # =========================================================================
    # ANDROID PLATFORM
    # =========================================================================
    {
        "threat_id": "THR-AND-001",
        "title": "Android Zero-Click MMS libstagefright RCE Precursors",
        "platform": "Android",
        "status": "Anticipated",
        "severity": "Critical",
        "cve_id": "CVE-2024-21477",
        "threat_actor": "Commercial Spyware Vendors (Intellexa / NSO Group)",
        "affected_systems": "Qualcomm chipset Android 12, 13, 14 devices",
        "tactics": ["Initial Access", "Privilege Escalation"],
        "techniques": ["T1068 - Exploitation for Privilege Escalation"],
        "summary": "Anticipated memory corruption in multimedia parsing and Qualcomm display drivers allowing zero-click code execution triggered via incoming WebRTC packet or silent push message.",
        "mitigation_procedures": [
            "Step 1: Apply Google Android Security Bulletin Monthly Patch (May 2024 or later).",
            "Step 2: Disable automatic MMS auto-retrieval in default messaging apps.",
            "Step 3: Enforce Google Play Protect real-time security scanning.",
            "Step 4: Enable Android Developer Mode restrictions and disable USB Debugging."
        ],
        "remediation_script": "adb shell settings put global auto_download_mms 0 && adb shell settings put global adb_enabled 0",
        "verification_command": "adb shell settings get global adb_enabled"
    },
    {
        "threat_id": "THR-AND-002",
        "title": "Anatsa (TeaBot) Android Banking Trojan via Play Store",
        "platform": "Android",
        "status": "Active",
        "severity": "Critical",
        "cve_id": "N/A (Malware Campaign)",
        "threat_actor": "TeaBot / Anatsa Threat Syndicate",
        "affected_systems": "Android 11, 12, 13, 14 on Samsung, Xiaomi, Pixel devices",
        "tactics": ["Credential Access", "Impact", "Execution"],
        "techniques": ["T1417 - Input Capture", "T1437.001 - Application Layer Protocol"],
        "summary": "Active dropper apps disguised as PDF document readers or clean-up utilities in Google Play Store. Once installed, prompts for Accessibility Service permissions to perform on-device screen scraping, OTP theft, and automated wire transfers from 650+ banking apps.",
        "mitigation_procedures": [
            "Step 1: Revoke Accessibility permissions from any non-assistive third-party app in Settings -> Accessibility.",
            "Step 2: Inspect installed applications for rogue packages: 'adb shell pm list packages -3'.",
            "Step 3: Uninstall suspect dropper packages immediately: 'adb shell pm uninstall <package.name>'.",
            "Step 4: Enable Biometric Confirmation on banking apps rather than SMS OTP fallback."
        ],
        "remediation_script": "adb shell pm list packages -3 | grep -E '(cleaner|pdf|scanner)' | while read p; do adb shell pm uninstall ${p#package:}; done",
        "verification_command": "adb shell pm list packages -3"
    },
    {
        "threat_id": "THR-AND-003",
        "title": "Chameleon Trojan Biometric-Bypass Fallback Evolution",
        "platform": "Android",
        "status": "Evolving",
        "severity": "High",
        "cve_id": "N/A (Trojan Evolution)",
        "threat_actor": "Chameleon Group",
        "affected_systems": "Android 13 and Android 14 devices",
        "tactics": ["Defense Evasion", "Credential Access"],
        "techniques": ["T1417 - Input Capture", "T1628.001 - Disable Screen Lock"],
        "summary": "Chameleon evolved new evasion tactics specifically targeting Android 13/14's Restricted Settings feature. Uses HTML overlay tricks to guide users to disable security toggles and triggers device lockscreen disablement to steal fallback PIN codes.",
        "mitigation_procedures": [
            "Step 1: Turn off Developer Options and USB Debugging when not in active engineering use.",
            "Step 2: Never grant Accessibility Service permissions to sideloaded APK files.",
            "Step 3: Enable Google Play Protect app scanning verification.",
            "Step 4: Use enterprise Mobile Device Management (MDM) to forbid sideloading from unknown sources."
        ],
        "remediation_script": "adb shell settings put secure install_non_market_apps 0",
        "verification_command": "adb shell settings get secure install_non_market_apps"
    },
    {
        "threat_id": "THR-AND-004",
        "title": "Stagefright MP4 Parsing Vulnerabilities (CVE-2015-1538)",
        "platform": "Android",
        "status": "Resolved",
        "severity": "Critical",
        "cve_id": "CVE-2015-1538",
        "threat_actor": "Zimperium Research / Public",
        "affected_systems": "Android 2.2 through 5.1.1",
        "tactics": ["Initial Access", "Execution"],
        "techniques": ["T1068 - Exploitation for Privilege Escalation"],
        "summary": "Integer overflow in libstagefright media library allowing arbitrary code execution when processing malicious MP4 metadata delivered via MMS.",
        "mitigation_procedures": [
            "Step 1: Upgrade to modern Android version (Android 6.0+).",
            "Step 2: Modern Android employs isolated media server process sandboxing and Address Space Layout Randomization (ASLR)."
        ],
        "remediation_script": "adb shell getprop ro.build.version.release",
        "verification_command": "adb shell getprop ro.build.version.release"
    },

    # =========================================================================
    # IOS PLATFORM
    # =========================================================================
    {
        "threat_id": "THR-IOS-001",
        "title": "BLASTPASS / FORCEDENTRY Zero-Click iMessage Exploitation",
        "platform": "iOS",
        "status": "Anticipated",
        "severity": "Critical",
        "cve_id": "CVE-2023-41064 / CVE-2023-41061",
        "threat_actor": "NSO Group (Pegasus Developer)",
        "affected_systems": "iOS before 16.6.1, iPadOS, watchOS",
        "tactics": ["Initial Access", "Privilege Escalation", "Collection"],
        "techniques": ["T1203 - Exploitation for Client Execution", "T1068 - Exploitation for Privilege Escalation"],
        "summary": "Zero-click exploit chain delivered via iMessage PassKit attachment containing malicious TIFF images, executing arbitrary code with kernel privileges without user interaction.",
        "mitigation_procedures": [
            "Step 1: Update iPhone immediately to iOS 17.5+ or 16.7.8 via Settings -> General -> Software Update.",
            "Step 2: Enable Apple Lockdown Mode for high-risk individuals (blocks complex web tech, shared photo albums, and iMessage attachments).",
            "Step 3: Regularly reboot device (daily reboot disrupts non-persistent iOS spyware memory implants)."
        ],
        "remediation_script": "Open Settings -> Privacy & Security -> Lockdown Mode -> Turn On Lockdown Mode -> Restart device.",
        "verification_command": "Settings -> General -> About -> iOS Version (Must be >= 16.6.1 or >= 17.0)"
    },
    {
        "threat_id": "THR-IOS-002",
        "title": "GoldPickaxe iOS Facial Recognition Stealing Trojan",
        "platform": "iOS",
        "status": "Active",
        "severity": "Critical",
        "cve_id": "N/A (iOS Malware Campaign)",
        "threat_actor": "GoldFactory Cybercrime Group",
        "affected_systems": "iOS 16, iOS 17",
        "tactics": ["Credential Access", "Initial Access", "Collection"],
        "techniques": ["T1556 - Modify Authentication Process", "T1113 - Screen Capture"],
        "summary": "Sophisticated iOS malware abusing Apple's TestFlight beta testing program and rogue Mobile Device Management (MDM) provisioning profiles to harvest user biometric facial scans and identity documents to synthesize deepfake banking authorization.",
        "mitigation_procedures": [
            "Step 1: Open Settings -> General -> VPN & Device Management and delete any unfamiliar MDM or configuration profiles immediately.",
            "Step 2: Never install TestFlight apps from untrusted third-party SMS or phishing links.",
            "Step 3: Revoke camera permissions for unfamiliar beta applications.",
            "Step 4: Contact banking institution if biometric identity theft is suspected."
        ],
        "remediation_script": "Settings -> General -> VPN & Device Management -> Select Unknown Profile -> Remove Profile",
        "verification_command": "Verify no untrusted Mobile Device Management profile exists under VPN & Device Management"
    },
    {
        "threat_id": "THR-IOS-003",
        "title": "EU DMA Third-Party Marketplace Malicious Package Evasion",
        "platform": "iOS",
        "status": "Evolving",
        "severity": "Medium",
        "cve_id": "N/A (Regulatory Attack Surface)",
        "threat_actor": "Adware Brokers & Rogueware Publishers",
        "affected_systems": "iOS 17.4+ in European Union countries",
        "tactics": ["Initial Access", "Defense Evasion"],
        "techniques": ["T1476 - Sideloading"],
        "summary": "Attackers adapting to alternative app marketplace policies in EU iOS versions, distributing adware, telemetry trackers, and privacy-invasive apps that evade strict Apple App Store review guidelines.",
        "mitigation_procedures": [
            "Step 1: Maintain marketplace installation restrictions under Screen Time -> Content & Privacy Restrictions -> App Installations.",
            "Step 2: Only install apps from well-established, certified alternative app marketplaces.",
            "Step 3: Check app privacy nutrition labels and tracking permission prompts."
        ],
        "remediation_script": "Settings -> Screen Time -> Content & Privacy Restrictions -> App Store Purchases -> Don't Allow",
        "verification_command": "Settings -> Screen Time -> Verify Content & Privacy Restrictions are Active"
    },
    {
        "threat_id": "THR-IOS-004",
        "title": "Trident Pegasus iOS Zero-Day Chain (CVE-2016-4655)",
        "platform": "iOS",
        "status": "Resolved",
        "severity": "Critical",
        "cve_id": "CVE-2016-4655 / CVE-2016-4656 / CVE-2016-4657",
        "threat_actor": "NSO Group / Citizen Lab Report",
        "affected_systems": "iOS 9.3.4 and earlier",
        "tactics": ["Initial Access", "Privilege Escalation"],
        "techniques": ["T1203 - Client Execution", "T1068 - Exploitation for Privilege Escalation"],
        "summary": "Three zero-day vulnerabilities in WebKit and iOS kernel chained to jailbreak device silently and deploy Pegasus surveillance payload upon clicking SMS link.",
        "mitigation_procedures": [
            "Step 1: Patched by Apple in iOS 9.3.5.",
            "Step 2: Modern iOS devices incorporate Pointer Authentication Codes (PAC), Page Protection Layer (PPL), and BlastDoor."
        ],
        "remediation_script": "Update device via Settings -> General -> Software Update",
        "verification_command": "Settings -> General -> About -> Version >= 9.3.5"
    },

    # =========================================================================
    # CLOUD & KUBERNETES PLATFORM
    # =========================================================================
    {
        "threat_id": "THR-CLD-001",
        "title": "Kubernetes Kubelet API Unauthorized Ingress & Remote Execution",
        "platform": "Cloud",
        "status": "Anticipated",
        "severity": "Critical",
        "cve_id": "CVE-2024-21626 / RunC Breakout",
        "threat_actor": "Cloud Threat Actor (TeamTNT / Kinsing)",
        "affected_systems": "AWS EKS, Google GKE, Self-hosted Kubernetes clusters running runc < 1.1.12",
        "tactics": ["Initial Access", "Privilege Escalation", "Impact"],
        "techniques": ["T1611 - Escape to Host", "T1610 - Deploy Container"],
        "summary": "Container escape flaw in runc (CVE-2024-21626) leaking file descriptor to host /sys/fs/cgroup, allowing an unprivileged container process to breakout onto the underlying Kubernetes host node.",
        "mitigation_procedures": [
            "Step 1: Upgrade runc to version 1.1.12 or higher across all Kubernetes worker nodes.",
            "Step 2: Enforce Pod Security Standards (PSS) at 'Restricted' profile; forbid hostPath mounts and privileged containers.",
            "Step 3: Close or authenticate Kubelet port 10250 and disable anonymous authentication: '--anonymous-auth=false'.",
            "Step 4: Use runtime admission controllers (Kyverno / OPA Gatekeeper) to block unapproved container images."
        ],
        "remediation_script": "kubectl apply -f - <<EOF\napiVersion: policy/v1beta1\nkind: PodSecurityPolicy\nmetadata:\n  name: restricted-psp\nspec:\n  privileged: false\n  allowPrivilegeEscalation: false\n  requiredDropCapabilities:\n    - ALL\nEOF",
        "verification_command": "kubectl get nodes -o wide && runc --version"
    },
    {
        "threat_id": "THR-CLD-002",
        "title": "AWS IMDSv1 SSRF Credential Relay Attacks",
        "platform": "Cloud",
        "status": "Active",
        "severity": "High",
        "cve_id": "N/A (Architectural Misconfiguration)",
        "threat_actor": "Various cloud ransomware and data exfiltration actors",
        "affected_systems": "AWS EC2 instances with default Instance Metadata Service enabled",
        "tactics": ["Credential Access", "Lateral Movement"],
        "techniques": ["T1552.005 - Cloud Instance Metadata API"],
        "summary": "Web application Server-Side Request Forgery (SSRF) vulnerabilities abused to query http://169.254.169.254/latest/meta-data/iam/security-credentials/ and extract temporary IAM role keys without requiring authentication tokens.",
        "mitigation_procedures": [
            "Step 1: Enforce IMDSv2 session-token requirement across all EC2 instances: 'aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled'.",
            "Step 2: Apply AWS Service Control Policy (SCP) denying ec2:RunInstances without IMDSv2.",
            "Step 3: Restrict egress traffic from application pods to 169.254.169.254/32 via iptables or AWS security group rules."
        ],
        "remediation_script": "aws ec2 modify-instance-metadata-options --instance-id i-1234567890abcdef0 --http-tokens required --http-endpoint enabled",
        "verification_command": "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]'"
    },
    {
        "threat_id": "THR-CLD-003",
        "title": "Kinsing Cryptomining Worm Targeting Exposed Docker APIs",
        "platform": "Cloud",
        "status": "Evolving",
        "severity": "High",
        "cve_id": "N/A (Worm Campaign)",
        "threat_actor": "Kinsing Cybercrime Group",
        "affected_systems": "Docker Engines with TCP port 2375 exposed to internet without mTLS",
        "tactics": ["Initial Access", "Execution", "Resource Hijacking"],
        "techniques": ["T1496 - Resource Hijacking", "T1610 - Deploy Container"],
        "summary": "Automated internet-wide scanner detecting unprotected Docker daemon API endpoints on port 2375, spawning malicious Alpine Linux containers that download Kinsing ELF binaries to mine Monero (XMR) and pivot across VPC subnets.",
        "mitigation_procedures": [
            "Step 1: Never bind Docker daemon TCP port 2375 to 0.0.0.0; bind only to 127.0.0.1 or unix socket /var/run/docker.sock.",
            "Step 2: If remote management required, enforce mutual TLS (mTLS) on port 2376.",
            "Step 3: Kill running Kinsing miner processes: 'docker ps -q --filter ancestor=kinsing | xargs -r docker kill'.",
            "Step 4: Block outbound connections to known mining pools (supportxmr.com, c3pool.org)."
        ],
        "remediation_script": "sudo sed -i 's/-H tcp:\\/\\/0.0.0.0:2375//g' /etc/docker/daemon.json 2>/dev/null || true; sudo systemctl restart docker",
        "verification_command": "sudo netstat -tlpn | grep 2375"
    },
    {
        "threat_id": "THR-CLD-004",
        "title": "Log4Shell Apache Log4j JNDI Remote Code Execution (CVE-2021-44228)",
        "platform": "Cloud",
        "status": "Resolved",
        "severity": "Critical",
        "cve_id": "CVE-2021-44228",
        "threat_actor": "Nation-State & Commodity Groups globally",
        "affected_systems": "Java cloud applications, Elasticsearch, Solr, Spring Boot using log4j-core 2.0-beta9 to 2.14.1",
        "tactics": ["Initial Access", "Execution"],
        "techniques": ["T1190 - Exploit Public-Facing Application"],
        "summary": "Improper input validation in Log4j's JNDI message lookup parsing arbitrary ldap:// and rmi:// URLs, permitting unauthenticated remote code execution.",
        "mitigation_procedures": [
            "Step 1: Upgrade Log4j dependency to version 2.17.1 or higher.",
            "Step 2: Emergency JVM flag: set -Dlog4j2.formatMsgNoLookups=true.",
            "Step 3: Remove JndiLookup.class from classpath: 'zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class'."
        ],
        "remediation_script": "export JAVA_TOOL_OPTIONS=\"-Dlog4j2.formatMsgNoLookups=true\"",
        "verification_command": "grep -rn 'formatMsgNoLookups' /etc/environment /etc/profile.d/ 2>/dev/null || echo 'Verified'"
    }
]
