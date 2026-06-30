#!/usr/bin/env python3
"""
MITRE ATT&CK Excel Mapping Generator
Scans every detection query file in the repository and generates an Excel workbook
with MITRE ATT&CK and D3FEND framework mappings.
"""

import os
import re
import sys
from pathlib import Path
from collections import Counter, defaultdict

try:
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
except ImportError:
    os.system("pip3 install openpyxl -q")
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Knowledge Base
# ---------------------------------------------------------------------------
ATTACK_TECHNIQUES = {
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries attempt to dump credentials to obtain account login and credential material.",
        "detection": "Monitor LSASS process access; alert on NTDS.dit file access; track credential dumping tools targeting LSASS.",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access credential material stored in LSASS process memory.",
        "detection": "Monitor for LSASS memory access; alert on procdump.exe targeting LSASS; enable Credential Guard.",
    },
    "T1003.003": {
        "name": "OS Credential Dumping: NTDS",
        "tactic": "Credential Access",
        "description": "Adversaries may access or create a copy of the Active Directory domain database to steal credentials.",
        "detection": "Monitor ntds.dit file access and shadow copy creation on domain controllers.",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or logical identifier on a network.",
        "detection": "Monitor for network scanning activity; alert on unusual SMB session creation; track net view commands.",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a service that accepts remote connections.",
        "detection": "Monitor remote service authentication; alert on lateral movement patterns such as admin shares.",
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to interact with remote network shares using SMB.",
        "detection": "Monitor SMB file copy events; alert on admin share access from unusual hosts; track PsExec patterns.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make executables or files difficult to discover by encoding or obfuscating their contents.",
        "detection": "Enable AMSI and Script Block Logging; monitor encoded PowerShell commands and high-entropy strings.",
    },
    "T1027.010": {
        "name": "Obfuscated Files or Information: Command Obfuscation",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate content during command execution to impede detection.",
        "detection": "Monitor for unusual character substitutions and concatenation in command lines; use AMSI for script detection.",
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "Discovery",
        "description": "Adversaries may sniff network traffic to capture information including authentication material.",
        "detection": "Monitor for promiscuous mode on network interfaces; alert on network capture tools (Wireshark, tcpdump, netsh trace).",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and network devices.",
        "detection": "Monitor for port scanning activity; alert on nmap-like patterns; track database service discovery commands.",
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "description": "Adversaries may abuse WMI to achieve execution.",
        "detection": "Monitor WMI activity; log wmiprvse.exe spawning child processes; alert on remote WMI invocations.",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than the existing C2 channel.",
        "detection": "Monitor for unusual outbound protocol usage; alert on large data transfers over DNS, ICMP, or non-standard channels.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "detection": "Monitor process creation for scripting interpreters; log command-line arguments; alert on unusual parent-child process relationships.",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "detection": "Enable PowerShell Script Block Logging (Event ID 4104); monitor for encoded commands (-EncodedCommand) and AMSI bypass attempts.",
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to discover group and permission settings.",
        "detection": "Monitor for net group/localgroup commands; alert on LDAP queries for group membership; track AD group enumeration tools.",
    },
    "T1069.001": {
        "name": "Permission Groups Discovery: Local Groups",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to find local system groups and permission settings.",
        "detection": "Monitor for net localgroup commands; alert on unusual local group enumeration activity.",
    },
    "T1069.003": {
        "name": "Permission Groups Discovery: Cloud Groups",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to find cloud groups and permission settings.",
        "detection": "Monitor Azure AD audit logs for bulk group membership queries; alert on AzureHound-like patterns.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols to blend in with existing traffic.",
        "detection": "Monitor for unusual application layer protocol usage; analyze network flows for C2 beaconing patterns.",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using HTTP/HTTPS to avoid detection by blending in with existing traffic.",
        "detection": "Monitor for C2 beaconing patterns in HTTP/HTTPS traffic; alert on Telegram API or unusual cloud services used for C2.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts to gain access.",
        "detection": "Monitor for suspicious account access, impossible travel, unusual login times/locations.",
    },
    "T1078.002": {
        "name": "Valid Accounts: Domain Accounts",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may obtain and abuse credentials of a domain account.",
        "detection": "Monitor for anomalous use of domain accounts; track privileged group membership changes.",
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of a cloud account.",
        "detection": "Monitor Azure AD sign-in logs for impossible travel, anomalous application access, failed MFA prompts.",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of accounts on a system or within an environment.",
        "detection": "Monitor for net user/localgroup commands; alert on LDAP enumeration; track bulk account queries via Graph API.",
    },
    "T1087.002": {
        "name": "Account Discovery: Domain Account",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of domain accounts.",
        "detection": "Monitor for unusual LDAP queries for user objects; alert on BloodHound/SharpHound-like enumeration.",
    },
    "T1087.004": {
        "name": "Account Discovery: Cloud Account",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of cloud accounts.",
        "detection": "Monitor Azure AD sign-in and audit logs; alert on bulk user download operations.",
    },
    "T1090": {
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may use a connection proxy to direct network traffic or act as intermediary.",
        "detection": "Monitor for proxy usage from unexpected endpoints; alert on anonymous proxy/VPN service usage.",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts to maintain access.",
        "detection": "Monitor for account changes: password resets, permission modifications, MFA changes, and OAuth grants.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools from an external system into a compromised environment.",
        "detection": "Monitor for certutil/bitsadmin/curl download patterns; alert on LOLBin-based file downloads.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "detection": "Monitor for multiple failed authentication attempts; alert on account lockouts across multiple accounts.",
    },
    "T1114": {
        "name": "Email Collection",
        "tactic": "Collection",
        "description": "Adversaries may target user email to collect sensitive information.",
        "detection": "Monitor email access patterns; alert on bulk email downloads or forwarding rule creation.",
    },
    "T1127.001": {
        "name": "Trusted Developer Utilities Proxy Execution: MSBuild",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility.",
        "detection": "Monitor MSBuild.exe for network connections and unusual child processes.",
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may modify access tokens to operate under a different security context.",
        "detection": "Monitor for token manipulation APIs; alert on RunAs usage with saved credentials.",
    },
    "T1134.002": {
        "name": "Access Token Manipulation: Create Process with Token",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may create a new process with an existing token to escalate privileges.",
        "detection": "Monitor for runas.exe with /savecred flag; track processes that spawn with a different user context.",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Adversaries may create an account to maintain access to victim systems.",
        "detection": "Monitor for account creation events; alert on accounts created outside approved provisioning workflows.",
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "Adversaries may create a local account to maintain access.",
        "detection": "Monitor Windows Event ID 4720; alert on net user /add commands; track local administrator group additions.",
    },
    "T1136.002": {
        "name": "Create Account: Domain Account",
        "tactic": "Persistence",
        "description": "Adversaries may create a domain account to maintain access.",
        "detection": "Monitor AD event ID 4720; alert on accounts created via command line.",
    },
    "T1136.003": {
        "name": "Create Account: Cloud Account",
        "tactic": "Persistence",
        "description": "Adversaries may create a cloud account to maintain access.",
        "detection": "Monitor Azure AD audit logs for user creation; alert on accounts that immediately receive elevated roles.",
    },
    "T1137": {
        "name": "Office Application Startup",
        "tactic": "Persistence",
        "description": "Adversaries may leverage Microsoft Office-based applications for persistence.",
        "detection": "Monitor for Office add-ins and COM objects being registered; alert on executable content launched by Office.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing host to access a network.",
        "detection": "Monitor application logs for exploitation attempts; alert on CVEs matching internet-exposed assets.",
    },
    "T1201": {
        "name": "Password Policy Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to access detailed information about password policies.",
        "detection": "Monitor for net accounts commands; alert on LDAP queries for password policy objects.",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": "Adversaries may bypass defenses by proxying execution of malicious content with signed binaries.",
        "detection": "Monitor LOLBins for unusual arguments or network activity; alert on signed binaries from non-standard locations.",
    },
    "T1218.010": {
        "name": "System Binary Proxy Execution: Regsvr32",
        "tactic": "Defense Evasion",
        "description": "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code.",
        "detection": "Monitor regsvr32.exe spawned by Office applications or from temp directories.",
    },
    "T1219": {
        "name": "Remote Access Software",
        "tactic": "Command and Control",
        "description": "Adversaries may use legitimate remote access software such as AnyDesk, TeamViewer, and LogMeIn.",
        "detection": "Monitor for unapproved remote access tools; alert on RAT/RMM tool installations; track unexpected remote access connections.",
    },
    "T1484": {
        "name": "Domain Policy Modification",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may modify the configuration settings of a domain to evade defenses or escalate privileges.",
        "detection": "Monitor Group Policy Object modifications; alert on changes to domain trust settings.",
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "description": "Adversaries may destroy data and files to interrupt availability.",
        "detection": "Monitor for mass file deletion events; alert on cloud resource deletion operations.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "detection": "Monitor for ransomware file rename patterns; alert on ASR ransomware rule triggers; track mass file modification.",
    },
    "T1489": {
        "name": "Service Stop",
        "tactic": "Impact",
        "description": "Adversaries may stop or disable services to render them unavailable.",
        "detection": "Monitor for service stop commands targeting critical services; alert on batch service termination.",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or disable built-in recovery data to prevent system recovery.",
        "detection": "Monitor for vssadmin/wmic shadowcopy delete commands; alert on BCDEdit modifications.",
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may backdoor web servers with web shells to establish persistent access.",
        "detection": "Monitor web server logs for unusual POST requests; alert on new executables in web directories.",
    },
    "T1518.001": {
        "name": "Software Discovery: Security Software Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of security software configurations installed on a system.",
        "detection": "Monitor WMIC queries targeting antivirus/security products; alert on Defender enumeration via PowerShell.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify system-level processes to execute malicious payloads for persistence.",
        "detection": "Monitor for new services or modified service configurations; alert on processes spawned from unusual locations.",
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by adding a program to Run keys or startup folder.",
        "detection": "Monitor registry modifications to HKCU/HKLM Run keys; alert on new entries in startup folders.",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may perform sudo caching or use sudoers file to elevate privileges.",
        "detection": "Monitor /etc/sudoers modifications; alert on users added to sudo group.",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
        "detection": "Monitor command-line activity for credential strings; alert on processes reading credential files.",
    },
    "T1553.005": {
        "name": "Subvert Trust Controls: Mark-of-the-Web Bypass",
        "tactic": "Defense Evasion",
        "description": "Adversaries may abuse specific file formats to subvert Mark-of-the-Web controls.",
        "detection": "Monitor for mounting of ISO/VHD/IMG files; alert on processes launched from mounted containers.",
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "tactic": "Persistence",
        "description": "Adversaries may modify authentication mechanisms to access user credentials or enable unauthorized access.",
        "detection": "Monitor for changes to authentication configuration; alert on conditional access policy modifications.",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "Adversaries may position themselves between two networked devices to intercept communications.",
        "detection": "Monitor for AiTM phishing patterns; alert on session cookie theft indicators; track impossible travel after authentication.",
    },
    "T1558.003": {
        "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "tactic": "Credential Access",
        "description": "Adversaries may abuse Kerberos tickets to obtain TGS tickets for offline password cracking.",
        "detection": "Monitor for TGS ticket requests for unusual SPNs; alert on RC4 downgrade in Kerberos TGS requests.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may modify components of a victim environment to hinder or disable defensive mechanisms.",
        "detection": "Monitor security product status changes; alert on antivirus/EDR disablement.",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversaries may modify or disable security tools to avoid detection.",
        "detection": "Monitor for Defender component disablement via PowerShell (Set-MpPreference); alert on EDR offboarding package downloads.",
    },
    "T1562.010": {
        "name": "Impair Defenses: Downgrade Attack",
        "tactic": "Defense Evasion",
        "description": "Adversaries may downgrade a version of system features that does not support updated security controls.",
        "detection": "Monitor Kerberos encryption type negotiations; alert on RC4 encryption usage in AES-configured environments.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "detection": "Monitor email gateway logs for suspicious attachments/links; correlate email delivery with subsequent process executions.",
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious attachment.",
        "detection": "Monitor for suspicious email attachments (macros, executables, ISO files); correlate email delivery with process creation.",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious link.",
        "detection": "Monitor for clicks on suspicious URLs; track browser-initiated downloads; alert on safe links triggers.",
    },
    "T1615": {
        "name": "Group Policy Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may gather information on Group Policy settings to identify privilege escalation paths.",
        "detection": "Monitor for gpresult and gpquery tool usage; alert on anomalous Group Policy enumeration from non-admin accounts.",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence.",
        "detection": "Monitor for log clearing events (Event ID 1102/104); alert on shadow copy deletion.",
    },
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs to hide intrusion activity.",
        "detection": "Alert on Event ID 1102 (Security log cleared) and 104 (System log cleared); monitor wevtutil.exe with clear-log arguments.",
    },
}

# ---------------------------------------------------------------------------
# Supporting lookup tables
# ---------------------------------------------------------------------------
TACTIC_IDS = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
    "Not Mapped": "",
}

TACTIC_SLUG = {
    "Initial Access": "initialaccess",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilegeescalation",
    "Defense Evasion": "defenseevasion",
    "Credential Access": "credentialaccess",
    "Discovery": "discovery",
    "Lateral Movement": "lateralmovement",
    "Collection": "collection",
    "Command and Control": "commandandcontrol",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
    "Not Mapped": "unmapped",
}

D3FEND_BY_TACTIC = {
    "Initial Access": {
        "primary": "Credential Hardening + Email Filtering + Platform Hardening",
        "techniques": [
            "Network Isolation (D3-NI): Restrict network exposure of services; limit inbound connectivity to essential paths.",
            "Platform Hardening (D3-PH): Apply patches, disable unnecessary features, enforce secure configurations on internet-facing systems.",
            "Credential Hardening (D3-CH): Enforce MFA on all external authentication; use phishing-resistant credentials (FIDO2/hardware tokens).",
            "Email Filtering (D3-EF): Deploy ATP email filtering to block malicious attachments and links before delivery.",
        ],
    },
    "Execution": {
        "primary": "Application Hardening + Script Execution Analysis",
        "techniques": [
            "Application Hardening (D3-AH): Implement application allowlisting to prevent unauthorized code execution.",
            "Execution Isolation (D3-EI): Use containerization, sandboxing, and process isolation to limit execution scope.",
            "Script Execution Analysis (D3-SEA): Enable AMSI and Script Block Logging to analyze and block malicious scripts.",
            "Platform Monitoring (D3-PM): Monitor process creation events, command-line arguments, and parent-child relationships.",
        ],
    },
    "Persistence": {
        "primary": "Platform Monitoring + Account Management",
        "techniques": [
            "Platform Hardening (D3-PH): Restrict registry key modification permissions; disable unnecessary startup locations.",
            "Boot Record Integrity (D3-BRI): Monitor and enforce integrity of boot records and startup configurations.",
            "Account Management (D3-AM): Enforce JIT/just-enough-access provisioning; audit accounts regularly.",
            "Platform Monitoring (D3-PM): Monitor for new scheduled tasks, services, and autostart registry key modifications.",
        ],
    },
    "Privilege Escalation": {
        "primary": "Privilege Restriction + Credential Hardening",
        "techniques": [
            "Credential Hardening (D3-CH): Use Privileged Access Workstations (PAW); enforce just-enough-access privilege model.",
            "Privilege Restriction (D3-PR): Implement least-privilege access; restrict local admin rights; use tiered admin model.",
            "User Account Control (D3-UAC): Enforce UAC for administrative operations; monitor elevation events.",
            "Platform Monitoring (D3-PM): Alert on token manipulation APIs; monitor sensitive group membership changes.",
        ],
    },
    "Defense Evasion": {
        "primary": "Platform Monitoring + Endpoint Health Beacon",
        "techniques": [
            "Platform Monitoring (D3-PM): Deploy EDR with behavioral detection; enable comprehensive process and file monitoring.",
            "Application Hardening (D3-AH): Block unsigned script execution; enforce WDAC/AppLocker policies.",
            "Endpoint Health Beacon (D3-EHB): Monitor security tool health status; alert on defensive tool tampering.",
            "Log Analysis (D3-LA): Centralize and protect log infrastructure; implement immutable logging.",
        ],
    },
    "Credential Access": {
        "primary": "Multi-Factor Authentication + Credential Hardening",
        "techniques": [
            "Credential Hardening (D3-CH): Enable Windows Credential Guard; use gMSA for service accounts; enforce strong password policies.",
            "Multi-Factor Authentication (D3-MFA): Deploy phishing-resistant MFA (FIDO2) for all privileged accounts.",
            "Credential Vault Management (D3-CVM): Use PAM solutions (CyberArk, Azure Key Vault); rotate credentials regularly.",
            "Platform Monitoring (D3-PM): Monitor LSASS access; alert on credential dumping tool patterns.",
        ],
    },
    "Discovery": {
        "primary": "Network Isolation + Platform Monitoring",
        "techniques": [
            "Network Isolation (D3-NI): Segment networks to limit lateral visibility; implement zero-trust network architecture.",
            "User Account Management (D3-UAM): Restrict enumeration rights; limit who can query directory services.",
            "Platform Monitoring (D3-PM): Alert on anomalous enumeration commands; monitor LDAP query volumes.",
            "Access Control (D3-AC): Implement RBAC; restrict access to directory enumeration APIs.",
        ],
    },
    "Lateral Movement": {
        "primary": "Network Isolation + Credential Hardening",
        "techniques": [
            "Network Isolation (D3-NI): Implement micro-segmentation; restrict SMB/WMI/RDP between workstations.",
            "Credential Hardening (D3-CH): Eliminate credential reuse; deploy LAPS for local admin accounts; use tiered admin model.",
            "Protocol Isolation (D3-PI): Block unnecessary lateral movement protocols at host-based firewall level.",
            "Platform Monitoring (D3-PM): Monitor remote authentication events; alert on admin share access patterns.",
        ],
    },
    "Collection": {
        "primary": "Data Loss Prevention + Access Control",
        "techniques": [
            "Data Loss Prevention (D3-DLP): Deploy DLP to detect and block sensitive data collection attempts.",
            "File Encryption (D3-FE): Encrypt sensitive data at rest to limit value of collected information.",
            "Access Control (D3-AC): Restrict access to sensitive data repositories; implement need-to-know access controls.",
            "Platform Monitoring (D3-PM): Monitor bulk file access and email forwarding rule creation.",
        ],
    },
    "Command and Control": {
        "primary": "Network Traffic Analysis + DNS Allowlisting",
        "techniques": [
            "Network Traffic Analysis (D3-NTA): Deploy NDR/NTA solutions to detect C2 beaconing and anomalous outbound connections.",
            "DNS Allowlisting (D3-DAL): Implement DNS sinkholes and allowlisting to block C2 domain resolution.",
            "Port Restriction (D3-PR): Block outbound connections to non-approved ports and protocols.",
            "Protocol Analysis (D3-PA): Inspect application layer protocols for C2 characteristics such as beaconing.",
        ],
    },
    "Exfiltration": {
        "primary": "Data Loss Prevention + Network Traffic Analysis",
        "techniques": [
            "Network Traffic Analysis (D3-NTA): Monitor for large or unusual outbound data transfers; detect protocol anomalies.",
            "Data Loss Prevention (D3-DLP): Implement DLP to detect and block sensitive data leaving the organization.",
            "Protocol Allowlisting (D3-PAL): Restrict outbound protocols to known-good; block unusual exfiltration channels.",
            "Endpoint Monitoring (D3-EM): Monitor for data staging and compression utilities used for exfiltration preparation.",
        ],
    },
    "Impact": {
        "primary": "Backup + Service Hardening",
        "techniques": [
            "Backup (D3-B): Maintain offline, immutable backups tested regularly for restoration capability.",
            "Data Recovery (D3-DR): Implement and test incident recovery procedures; use versioned storage.",
            "Service Hardening (D3-SH): Restrict which processes can stop critical services; implement service integrity monitoring.",
            "Platform Monitoring (D3-PM): Alert on shadow copy deletion, mass file modification, and service termination events.",
        ],
    },
    "Not Mapped": {
        "primary": "Platform Monitoring + Access Control",
        "techniques": [
            "Platform Monitoring (D3-PM): Monitor for anomalous system and network activity.",
            "Access Control (D3-AC): Apply least-privilege principles to limit attack surface.",
            "Network Isolation (D3-NI): Segment networks and restrict lateral connectivity.",
            "Endpoint Health Beacon (D3-EHB): Ensure security tooling is healthy and active on endpoints.",
        ],
    },
}

TACTIC_COLORS = {
    "Initial Access":       "FF4C6EF5",
    "Execution":            "FFFA8231",
    "Persistence":          "FF20C997",
    "Privilege Escalation": "FFAE3EC9",
    "Defense Evasion":      "FFFD7E14",
    "Credential Access":    "FFFA5252",
    "Discovery":            "FF4DABF7",
    "Lateral Movement":     "FF339AF0",
    "Collection":           "FF94D82D",
    "Command and Control":  "FFE64980",
    "Exfiltration":         "FFFF6B6B",
    "Impact":               "FFE03131",
    "Not Mapped":           "FF868E96",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def slugify(text):
    text = re.sub(r"[^a-z0-9]", "-", text.lower())
    return re.sub(r"-+", "-", text).strip("-")


def read_file_safe(path):
    for enc in ("utf-8", "latin-1"):
        try:
            return Path(path).read_text(encoding=enc)
        except Exception:
            continue
    return ""


def extract_title(content):
    m = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    return m.group(1).strip() if m else ""


def extract_description(content):
    m = re.search(
        r"####\s+Description\s*\n(.*?)(?=\n####|\n##|\Z)",
        content, re.DOTALL | re.IGNORECASE,
    )
    if m:
        desc = re.sub(r"\s+", " ", m.group(1)).strip()
        return desc[:600] + "…" if len(desc) > 600 else desc
    return ""


def extract_risk(content):
    m = re.search(
        r"####\s+Risk\s*\n(.*?)(?=\n####|\n##|\Z)",
        content, re.DOTALL | re.IGNORECASE,
    )
    if m:
        risk = re.sub(r"\s+", " ", m.group(1)).strip()
        return risk[:400] + "…" if len(risk) > 400 else risk
    return ""


def extract_platforms(content):
    found = []
    for name in [
        "Defender For Endpoint", "Sentinel", "Defender For Identity",
        "Defender For Cloud Apps", "Graph API", "Azure Active Directory",
        "Defender XDR", "Log Analytics", "Azure Resource Graph",
    ]:
        if re.search(r"##\s+" + re.escape(name), content, re.IGNORECASE):
            found.append(name)
    return found if found else ["Unknown"]


def extract_mitre_table(content):
    """
    Parse the MITRE ATT&CK table inside a markdown file.
    Returns list of (technique_id, technique_name) tuples.
    """
    results = []
    # Find the MITRE section
    m = re.search(
        r"####\s+MITRE ATT&CK Technique\(s\)(.*?)(?=\n####|\n##|\Z)",
        content, re.DOTALL | re.IGNORECASE,
    )
    if not m:
        return results

    table_text = m.group(1)
    # Match table rows: | T1234 | Name | ... |
    for row in re.finditer(
        r"\|\s*(T\d{4}(?:\.\d{3})?)\s*\|\s*([^|]+?)\s*\|",
        table_text, re.IGNORECASE,
    ):
        tid = row.group(1).upper().strip()
        tname = row.group(2).strip()
        if tid not in [r[0] for r in results]:
            results.append((tid, tname))
    return results


def infer_category(file_path, repo_root):
    """Determine category label from the folder structure."""
    rel = file_path.relative_to(repo_root)
    parts = rel.parts
    return parts[0] if len(parts) > 1 else "Other"


# ---------------------------------------------------------------------------
# Build records from every .md file in the repo
# ---------------------------------------------------------------------------

SKIP_FILES = {
    "README.md", "DetectionTemplate.md",
    "Mapping.md", "TheArtOfKnowingYourData.md",
}
SKIP_DIRS = {"MITRE ATT&CK", "Functions", "KQL Regex", "Learning", "MISP", "Fun"}


def collect_all_records(repo_root):
    records = []
    repo_root = Path(repo_root)
    all_md = sorted(repo_root.rglob("*.md"))

    for md_path in all_md:
        # Skip special files
        if md_path.name in SKIP_FILES:
            continue
        # Skip skipped directories
        rel_parts = md_path.relative_to(repo_root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue

        content = read_file_safe(md_path)
        if not content:
            continue

        title = extract_title(content) or md_path.stem
        description = extract_description(content)
        risk = extract_risk(content)
        platforms = extract_platforms(content)
        category = infer_category(md_path, repo_root)
        rel_display = str(md_path.relative_to(repo_root))

        mitre_entries = extract_mitre_table(content)

        if mitre_entries:
            # Create one row per technique
            for tech_id, tech_name_from_file in mitre_entries:
                tech_info = ATTACK_TECHNIQUES.get(tech_id, {})
                # Try parent if sub-technique not found
                if not tech_info and "." in tech_id:
                    tech_info = ATTACK_TECHNIQUES.get(tech_id.split(".")[0], {})

                tactic = tech_info.get("tactic", "Unknown")
                if tactic == "Unknown":
                    # Try to infer from technique name
                    tactic = "Not Mapped"

                tech_name = tech_info.get("name", tech_name_from_file)
                tech_desc = tech_info.get(
                    "description",
                    f"See https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                )
                detection = tech_info.get(
                    "detection",
                    "Monitor relevant telemetry for anomalous activity associated with this technique.",
                )
                tech_url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"

                d3_info = D3FEND_BY_TACTIC.get(tactic, D3FEND_BY_TACTIC["Not Mapped"])
                tactic_slug = TACTIC_SLUG.get(tactic, slugify(tactic))
                canonical = f"{tactic_slug}-{slugify(title)}"

                records.append({
                    "Canonical Name": canonical,
                    "Query Title": title,
                    "Category": category,
                    "MITRE Tactic": tactic,
                    "Tactic ID": TACTIC_IDS.get(tactic, ""),
                    "Technique ID": tech_id,
                    "Technique Name": tech_name,
                    "Technique Description": tech_desc,
                    "ATT&CK Technique URL": tech_url,
                    "Detection Strategy (ATT&CK)": detection,
                    "D3FEND Primary Strategy": d3_info.get("primary", ""),
                    "D3FEND Defensive Techniques": "\n".join(d3_info.get("techniques", [])),
                    "D3FEND URL": "https://d3fend.mitre.org/",
                    "Platforms": ", ".join(platforms),
                    "Query Description": description,
                    "Risk": risk,
                    "File Path": rel_display,
                })
        else:
            # No MITRE mapping — include with Not Mapped tactic
            d3_info = D3FEND_BY_TACTIC["Not Mapped"]
            category_slug = slugify(category)
            canonical = f"unmapped-{slugify(title)}"

            records.append({
                "Canonical Name": canonical,
                "Query Title": title,
                "Category": category,
                "MITRE Tactic": "Not Mapped",
                "Tactic ID": "",
                "Technique ID": "",
                "Technique Name": "",
                "Technique Description": "",
                "ATT&CK Technique URL": "",
                "Detection Strategy (ATT&CK)": "",
                "D3FEND Primary Strategy": d3_info.get("primary", ""),
                "D3FEND Defensive Techniques": "\n".join(d3_info.get("techniques", [])),
                "D3FEND URL": "https://d3fend.mitre.org/",
                "Platforms": ", ".join(platforms),
                "Query Description": description,
                "Risk": risk,
                "File Path": rel_display,
            })

    return records


# ---------------------------------------------------------------------------
# Excel generation
# ---------------------------------------------------------------------------

COLUMNS = [
    "Canonical Name",
    "Query Title",
    "Category",
    "MITRE Tactic",
    "Tactic ID",
    "Technique ID",
    "Technique Name",
    "Technique Description",
    "ATT&CK Technique URL",
    "Detection Strategy (ATT&CK)",
    "D3FEND Primary Strategy",
    "D3FEND Defensive Techniques",
    "D3FEND URL",
    "Platforms",
    "Query Description",
    "Risk",
    "File Path",
]

COLUMN_WIDTHS = {
    "Canonical Name": 45,
    "Query Title": 42,
    "Category": 25,
    "MITRE Tactic": 22,
    "Tactic ID": 12,
    "Technique ID": 14,
    "Technique Name": 44,
    "Technique Description": 70,
    "ATT&CK Technique URL": 55,
    "Detection Strategy (ATT&CK)": 70,
    "D3FEND Primary Strategy": 45,
    "D3FEND Defensive Techniques": 80,
    "D3FEND URL": 32,
    "Platforms": 40,
    "Query Description": 70,
    "Risk": 55,
    "File Path": 60,
}


def thin_border():
    s = Side(style="thin", color="FFD0D0D0")
    return Border(left=s, right=s, top=s, bottom=s)


def write_header_row(ws, row, columns, fill_color, font_color="FFFFFFFF"):
    fill = PatternFill("solid", fgColor=fill_color)
    font = Font(name="Calibri", bold=True, color=font_color, size=11)
    align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    for col_idx, col_name in enumerate(columns, start=1):
        c = ws.cell(row=row, column=col_idx, value=col_name)
        c.fill = fill
        c.font = font
        c.alignment = align
        c.border = thin_border()
    ws.row_dimensions[row].height = 30


def write_data_rows(ws, records, columns, start_row=2):
    wrap = Alignment(vertical="top", wrap_text=True)
    alt_fill = PatternFill("solid", fgColor="FFF8F9FA")

    for row_idx, record in enumerate(records, start=start_row):
        tactic = record.get("MITRE Tactic", "Not Mapped")
        tac_color = TACTIC_COLORS.get(tactic, "FF868E96")

        for col_idx, col_name in enumerate(columns, start=1):
            val = record.get(col_name, "")
            c = ws.cell(row=row_idx, column=col_idx, value=val)
            c.alignment = wrap
            c.border = thin_border()

            if col_name == "MITRE Tactic":
                c.fill = PatternFill("solid", fgColor=tac_color)
                c.font = Font(color="FFFFFFFF", bold=True)
            elif row_idx % 2 == 0:
                c.fill = alt_fill


def set_column_widths(ws, columns):
    for col_idx, col_name in enumerate(columns, start=1):
        ws.column_dimensions[get_column_letter(col_idx)].width = COLUMN_WIDTHS.get(col_name, 30)


def write_excel(records, output_path):
    wb = openpyxl.Workbook()

    # ---- Summary sheet ----
    ws_sum = wb.active
    ws_sum.title = "Summary"

    title_font = Font(name="Calibri", size=16, bold=True, color="FF2F4F8F")
    ws_sum["A1"] = "MITRE ATT&CK Detection & D3FEND Mapping"
    ws_sum["A1"].font = title_font
    ws_sum["A2"] = "Repository: Hunting-Queries-Detection-Rules (github.com/Bert-JanP)"
    ws_sum["A3"] = f"Total Query Files: {len(set(r['File Path'] for r in records))}"
    ws_sum["A4"] = f"Total Query-Technique Rows: {len(records)}"
    ws_sum["A5"] = f"MITRE-Mapped Queries: {sum(1 for r in records if r['MITRE Tactic'] != 'Not Mapped')}"
    ws_sum["A6"] = f"Unmapped Queries: {sum(1 for r in records if r['MITRE Tactic'] == 'Not Mapped')}"

    ws_sum["A8"] = "Tactic"
    ws_sum["B8"] = "Rows"
    ws_sum["C8"] = "Unique Files"
    for cell, color in [(ws_sum["A8"], "FF2F4F8F"), (ws_sum["B8"], "FF2F4F8F"), (ws_sum["C8"], "FF2F4F8F")]:
        cell.fill = PatternFill("solid", fgColor=color)
        cell.font = Font(bold=True, color="FFFFFFFF")

    tactic_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact", "Not Mapped",
    ]
    tactic_file_counts = defaultdict(set)
    tactic_row_counts = Counter()
    for r in records:
        t = r["MITRE Tactic"]
        tactic_row_counts[t] += 1
        tactic_file_counts[t].add(r["File Path"])

    for i, tactic in enumerate(tactic_order, start=9):
        if tactic not in tactic_row_counts:
            continue
        ws_sum.cell(row=i, column=1, value=tactic)
        ws_sum.cell(row=i, column=2, value=tactic_row_counts[tactic])
        ws_sum.cell(row=i, column=3, value=len(tactic_file_counts[tactic]))
        col = TACTIC_COLORS.get(tactic, "FF868E96")
        ws_sum.cell(row=i, column=1).fill = PatternFill("solid", fgColor=col)
        ws_sum.cell(row=i, column=1).font = Font(color="FFFFFFFF", bold=True)

    for col, w in [("A", 28), ("B", 10), ("C", 16)]:
        ws_sum.column_dimensions[col].width = w

    # ---- Full mapping sheet ----
    ws_all = wb.create_sheet(title="All Queries")
    write_header_row(ws_all, 1, COLUMNS, "FF2F4F8F")
    write_data_rows(ws_all, records, COLUMNS, start_row=2)
    ws_all.freeze_panes = "A2"
    ws_all.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}1"
    set_column_widths(ws_all, COLUMNS)

    # ---- MITRE-mapped only sheet ----
    mapped = [r for r in records if r["MITRE Tactic"] != "Not Mapped"]
    ws_mapped = wb.create_sheet(title="MITRE Mapped")
    write_header_row(ws_mapped, 1, COLUMNS, "FF2F4F8F")
    write_data_rows(ws_mapped, mapped, COLUMNS, start_row=2)
    ws_mapped.freeze_panes = "A2"
    ws_mapped.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}1"
    set_column_widths(ws_mapped, COLUMNS)

    # ---- Per-tactic sheets ----
    by_tactic = defaultdict(list)
    for r in records:
        by_tactic[r["MITRE Tactic"]].append(r)

    for tactic in tactic_order:
        tactic_records = by_tactic.get(tactic, [])
        if not tactic_records:
            continue

        sheet_name = tactic[:31]
        ws_t = wb.create_sheet(title=sheet_name)
        tac_color = TACTIC_COLORS.get(tactic, "FF868E96")

        # Banner row
        ws_t.merge_cells(f"A1:{get_column_letter(len(COLUMNS))}1")
        banner = ws_t["A1"]
        banner.value = (
            f"MITRE ATT&CK: {tactic}  |  {TACTIC_IDS.get(tactic, 'N/A')}  |  "
            f"Queries: {len(tactic_records)}"
        )
        banner.font = Font(name="Calibri", size=13, bold=True, color="FFFFFFFF")
        banner.fill = PatternFill("solid", fgColor=tac_color)
        banner.alignment = Alignment(horizontal="center", vertical="center")
        ws_t.row_dimensions[1].height = 26

        # D3FEND summary row
        d3_info = D3FEND_BY_TACTIC.get(tactic, D3FEND_BY_TACTIC["Not Mapped"])
        ws_t.merge_cells(f"A2:{get_column_letter(len(COLUMNS))}2")
        d3_cell = ws_t["A2"]
        d3_cell.value = f"D3FEND Primary Defense: {d3_info.get('primary', '')}"
        d3_cell.font = Font(bold=True, color="FF2F4F8F", size=10)
        d3_cell.alignment = Alignment(horizontal="left", vertical="center")
        ws_t.row_dimensions[2].height = 18

        # Column headers
        write_header_row(ws_t, 3, COLUMNS, tac_color)
        write_data_rows(ws_t, tactic_records, COLUMNS, start_row=4)

        ws_t.freeze_panes = "A4"
        ws_t.auto_filter.ref = f"A3:{get_column_letter(len(COLUMNS))}3"
        set_column_widths(ws_t, COLUMNS)

    wb.save(output_path)
    print(f"\n✓ Excel file saved: {output_path}")
    print(f"  Total rows    : {len(records)}")
    print(f"  MITRE mapped  : {len(mapped)}")
    print(f"  Not mapped    : {len(records) - len(mapped)}")
    print(f"  Sheets        : {len(wb.sheetnames)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    repo_root = Path(__file__).parent.parent.resolve()
    print(f"Repository root : {repo_root}")
    print("Scanning all .md files …")

    records = collect_all_records(repo_root)

    # Sort: tactic order → technique ID → title
    tactic_order_map = {t: i for i, t in enumerate([
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact", "Not Mapped",
    ])}
    records.sort(key=lambda r: (
        tactic_order_map.get(r["MITRE Tactic"], 99),
        r.get("Technique ID", ""),
        r["Query Title"].lower(),
    ))

    output_path = repo_root / "MITRE ATT&CK" / "MITRE_ATT&CK_Detection_D3FEND_Mapping.xlsx"
    write_excel(records, output_path)


if __name__ == "__main__":
    main()
