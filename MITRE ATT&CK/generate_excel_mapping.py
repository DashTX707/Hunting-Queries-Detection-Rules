#!/usr/bin/env python3
"""
MITRE ATT&CK Excel Mapping Generator
Parses all detection queries in the repository and generates an Excel workbook
with MITRE ATT&CK and D3FEND framework mappings.
"""

import os
import re
import sys
from pathlib import Path

try:
    import openpyxl
    from openpyxl.styles import (
        PatternFill, Font, Alignment, Border, Side
    )
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.table import Table, TableStyleInfo
except ImportError:
    print("Installing openpyxl...")
    os.system("pip3 install openpyxl -q")
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.table import Table, TableStyleInfo

# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Knowledge Base
# Technique ID -> {name, tactic, description, detection_strategy}
# ---------------------------------------------------------------------------
ATTACK_TECHNIQUES = {
    # Initial Access
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "detection": "Monitor for suspicious account access, impossible travel, unusual login times/locations, and authentication failures followed by success.",
    },
    "T1078.001": {
        "name": "Valid Accounts: Default Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "detection": "Monitor authentication events for default account usage; audit enabled default accounts.",
    },
    "T1078.002": {
        "name": "Valid Accounts: Domain Accounts",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may obtain and abuse credentials of a domain account. Domain accounts can have broad access across systems in an Active Directory environment.",
        "detection": "Monitor for anomalous use of domain accounts; track privileged group membership changes; correlate logon events with expected behavior baselines.",
    },
    "T1078.003": {
        "name": "Valid Accounts: Local Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "detection": "Monitor local account logon events and account creation; audit local admin group membership.",
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of a cloud account. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration.",
        "detection": "Monitor Azure AD sign-in logs for impossible travel, anomalous application access, failed MFA prompts, and suspicious OAuth grants.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing host or system to initially access a network.",
        "detection": "Monitor application logs for exploitation attempts; alert on CVEs matching internet-exposed assets; track patch status of public-facing systems.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems. Phishing is the practice of tricking a person into providing information or taking an action that would normally not occur.",
        "detection": "Monitor email gateway logs for suspicious attachments/links; track user-reported phishing; correlate email delivery with subsequent process executions.",
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing.",
        "detection": "Monitor for suspicious email attachments (macros, executables, ISO files, LNK files); correlate email delivery with process creation events on endpoints.",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing links are a variant of spearphishing.",
        "detection": "Monitor for clicks on suspicious URLs in email; track browser-initiated downloads; alert on safe links triggers and redirects to credential-harvesting sites.",
    },
    # Execution
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "description": "Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution. WMI is a Windows administration feature that provides a uniform environment for local and remote access.",
        "detection": "Monitor WMI activity (WmiPrvSE.exe process creation, WMI event subscriptions); log wmiprvse.exe spawning child processes; alert on remote WMI invocations.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems.",
        "detection": "Monitor process creation for scripting interpreters; log command-line arguments; alert on encoded commands, unusual parent-child process relationships.",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.",
        "detection": "Enable PowerShell Script Block Logging (Event ID 4104); monitor for encoded commands (-EncodedCommand), AMSI bypass attempts, download cradles, and suspicious module imports.",
    },
    # Persistence
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account.",
        "detection": "Monitor for account changes: password resets, permission modifications, MFA changes, and OAuth application grants. Alert on changes made outside normal change windows.",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access.",
        "detection": "Monitor for account creation events (Event ID 4720 for Windows, cloud audit logs for AAD); alert on accounts created outside approved provisioning workflows.",
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration.",
        "detection": "Monitor Windows Event ID 4720; alert on net user /add commands; track local administrator group additions.",
    },
    "T1136.002": {
        "name": "Create Account: Domain Account",
        "tactic": "Persistence",
        "description": "Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems.",
        "detection": "Monitor AD event ID 4720 for domain account creation; alert on accounts created via command line; track provisioning outside HR/IT workflows.",
    },
    "T1136.003": {
        "name": "Create Account: Cloud Account",
        "tactic": "Persistence",
        "description": "Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access.",
        "detection": "Monitor Azure AD audit logs for user creation; alert on accounts created by service principals or apps; track accounts that immediately receive elevated roles.",
    },
    "T1137": {
        "name": "Office Application Startup",
        "tactic": "Persistence",
        "description": "Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems.",
        "detection": "Monitor for Office add-ins and COM objects being registered; alert on executable content launched by Office applications; review Office startup folder contents.",
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may backdoor web servers with web shells to establish persistent access to systems. A web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway.",
        "detection": "Monitor web server logs for unusual POST requests to static files; alert on new executable files in web directories; inspect web server child process spawning.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.",
        "detection": "Monitor for new services or modified service configurations; audit scheduled tasks; alert on processes spawned from unusual parent processes or locations.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges.",
        "detection": "Monitor registry Run keys, startup folders, and scheduled tasks for modifications; alert on new autostart entries created outside normal software installation.",
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the 'run keys' in the Registry or startup folder will cause the program referenced to be executed when a user logs in.",
        "detection": "Monitor registry modifications to HKCU/HKLM Run keys; alert on new entries in startup folders; correlate with process execution at next login.",
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "tactic": "Persistence",
        "description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.",
        "detection": "Monitor for changes to authentication configuration; alert on conditional access policy modifications; audit authentication provider changes.",
    },
    # Privilege Escalation
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls.",
        "detection": "Monitor for token manipulation APIs; alert on RunAs usage with saved credentials; track processes that spawn child processes with different security contexts.",
    },
    "T1134.002": {
        "name": "Access Token Manipulation: Create Process with Token",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may create a new process with an existing token to escalate privileges and bypass access controls.",
        "detection": "Monitor for runas.exe with /savecred flag; track CreateProcessWithTokenW API calls; alert on processes that spawn with a different user context than the parent.",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.",
        "detection": "Monitor for UAC bypass techniques; alert on sudo group membership additions; track elevation events outside normal workflows.",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges.",
        "detection": "Monitor /etc/sudoers modifications; alert on users added to sudo/sudoers group; track sudo command usage especially for unusual commands.",
    },
    # Defense Evasion
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
        "detection": "Enable AMSI and Script Block Logging; monitor for encoded PowerShell commands, packed binaries, and high-entropy strings in command lines.",
    },
    "T1027.010": {
        "name": "Obfuscated Files or Information: Command Obfuscation",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obfuscate content during command execution to impede detection. Command-line obfuscation is a method of making strings and concatenation unpredictable to both automated and manual analysis.",
        "detection": "Monitor for unusual character substitutions, concatenation patterns, and environment variable manipulation in command lines; use AMSI for script-level detection.",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses.",
        "detection": "Monitor for log clearing events (Event ID 1102/104); alert on shadow copy deletion; track file deletion in sensitive directories.",
    },
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs to hide the activity of an intrusion.",
        "detection": "Alert on Event ID 1102 (Security log cleared) and 104 (System log cleared); monitor wevtutil.exe invocations with 'cl' or 'clear-log' arguments.",
    },
    "T1127.001": {
        "name": "Trusted Developer Utilities Proxy Execution: MSBuild",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe can be abused to execute arbitrary code when supplied an inline task.",
        "detection": "Monitor MSBuild.exe for network connections and unusual child processes; alert on MSBuild spawned from unexpected parent processes or locations.",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries.",
        "detection": "Monitor LOLBins (mshta, regsvr32, certutil, wmic, etc.) for unusual arguments or network activity; alert on signed binaries executing from non-standard locations.",
    },
    "T1218.010": {
        "name": "System Binary Proxy Execution: Regsvr32",
        "tactic": "Defense Evasion",
        "description": "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls.",
        "detection": "Monitor regsvr32.exe spawned by Office applications or from temp directories; alert on regsvr32 with URL arguments (/i:http://).",
    },
    "T1553.005": {
        "name": "Subvert Trust Controls: Mark-of-the-Web Bypass",
        "tactic": "Defense Evasion",
        "description": "Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls. ISO and VHD container files are common methods to deliver malware bypassing MOTW.",
        "detection": "Monitor for mounting of ISO/VHD/IMG files; alert on processes launched from mounted containers; track rare ISO file execution patterns.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.",
        "detection": "Monitor security product status changes; alert on antivirus/EDR disablement; track conditional access policy modifications.",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.",
        "detection": "Monitor for Defender component disablement via PowerShell (Set-MpPreference); alert on EDR offboarding package downloads; track security tool process terminations.",
    },
    "T1562.010": {
        "name": "Impair Defenses: Downgrade Attack",
        "tactic": "Defense Evasion",
        "description": "Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls.",
        "detection": "Monitor Kerberos encryption type negotiations; alert on RC4 encryption usage in environments configured for AES; detect protocol downgrade patterns.",
    },
    # Credential Access
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.",
        "detection": "Monitor LSASS process access; alert on NTDS.dit file access; track tools like Mimikatz, ProcDump targeting LSASS; monitor SAM/SYSTEM hive access.",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
        "detection": "Monitor for LSASS process memory access; alert on procdump.exe targeting LSASS; enable Credential Guard; monitor for Mimikatz-related process patterns.",
    },
    "T1003.003": {
        "name": "OS Credential Dumping: NTDS",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information.",
        "detection": "Monitor ntds.dit file access and shadow copy creation of domain controllers; alert on vssadmin create shadow commands on DCs.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "detection": "Monitor for multiple failed authentication attempts followed by success; alert on account lockouts across multiple accounts; track authentication rate anomalies.",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
        "detection": "Monitor command-line activity for credential strings; alert on processes reading credential files; scan for cleartext passwords in process arguments.",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors.",
        "detection": "Monitor for AiTM phishing patterns; alert on session cookie theft indicators; track impossible travel after authentication; monitor for Evilginx/Modlishka-style proxy patterns.",
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets.",
        "detection": "Monitor Kerberos ticket requests; alert on golden/silver ticket anomalies (unusual encryption, unusually long ticket lifetimes); track Kerberoasting patterns.",
    },
    "T1558.003": {
        "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "tactic": "Credential Access",
        "description": "Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to offline password cracking.",
        "detection": "Monitor for requests for TGS tickets for SPNs not associated with the requesting account's normal usage; alert on RC4 downgrade in Kerberos TGS requests.",
    },
    # Discovery
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network for lateral movement.",
        "detection": "Monitor for network scanning activity; alert on unusual SMB session creation patterns; track net view and similar enumeration commands.",
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "Discovery",
        "description": "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.",
        "detection": "Monitor for promiscuous mode on network interfaces; alert on network capture tools (Wireshark, tcpdump, netsh trace); track raw socket usage.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
        "detection": "Monitor for port scanning activity; alert on nmap-like patterns in network traffic; track database service discovery commands.",
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
        "detection": "Monitor for net localgroup commands and PowerShell Get-LocalGroup; alert on unusual local group enumeration activity.",
    },
    "T1069.003": {
        "name": "Permission Groups Discovery: Cloud Groups",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to find cloud groups and permission settings.",
        "detection": "Monitor Azure AD audit logs for bulk group membership queries; alert on AzureHound or similar tool patterns; track high-volume Graph API calls.",
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
        "detection": "Monitor for unusual LDAP queries for user objects; alert on BloodHound/SharpHound-like enumeration patterns; track anomalous DC LDAP traffic.",
    },
    "T1087.004": {
        "name": "Account Discovery: Cloud Account",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of cloud accounts.",
        "detection": "Monitor Azure AD sign-in and audit logs; alert on bulk user download operations; track applications performing high-volume user enumeration.",
    },
    "T1201": {
        "name": "Password Policy Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to access detailed information about the password policy used within an enterprise network.",
        "detection": "Monitor for net accounts commands; alert on LDAP queries for password policy objects; track domain policy enumeration.",
    },
    "T1518.001": {
        "name": "Software Discovery: Security Software Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment.",
        "detection": "Monitor WMIC queries targeting antivirus/security products; alert on Defender enumeration via PowerShell; track security software inventory queries.",
    },
    "T1615": {
        "name": "Group Policy Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security misconfigurations, or exploitation.",
        "detection": "Monitor for gpresult and gpquery tool usage; alert on anomalous Group Policy enumeration from non-admin accounts; track LDAP queries for GPO objects.",
    },
    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC.",
        "detection": "Monitor remote service authentication; alert on lateral movement patterns (admin shares, PSExec, WMI remote execution); track unusual service connections.",
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.",
        "detection": "Monitor SMB file copy events; alert on admin share access from unusual hosts; track PsExec and similar tools targeting remote shares.",
    },
    # Collection
    "T1114": {
        "name": "Email Collection",
        "tactic": "Collection",
        "description": "Adversaries may target user email to collect sensitive information.",
        "detection": "Monitor email access patterns; alert on bulk email downloads or forwarding rules creation; track access from unusual locations or devices.",
    },
    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection by blending in with existing traffic.",
        "detection": "Monitor for unusual application layer protocol usage; analyze network flows for C2 beaconing patterns; track connections to rare external destinations.",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using HTTP/HTTPS application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "detection": "Monitor for C2 beaconing patterns in HTTP/HTTPS traffic; alert on connections to Telegram API or unusual cloud services for C2; track periodic/automated connection patterns.",
    },
    "T1090": {
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications.",
        "detection": "Monitor for proxy usage from unexpected endpoints; alert on anonymous proxy/VPN service usage; track connections through unusual intermediary services.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
        "detection": "Monitor for certutil/bitsadmin/curl download patterns; alert on LOLBin-based file downloads; track new executable arrivals from network locations.",
    },
    "T1219": {
        "name": "Remote Access Software",
        "tactic": "Command and Control",
        "description": "Adversaries may use legitimate desktop support and remote access software, such as Team Viewer, AnyDesk, and LogMeIn, as means of command and control.",
        "detection": "Monitor for unapproved remote access tools; alert on RAT/RMM tool installations from unusual sources; track unexpected remote access connections to external IPs.",
    },
    # Exfiltration
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.",
        "detection": "Monitor for unusual outbound protocol usage; alert on large data transfers over DNS, ICMP, or other non-standard channels.",
    },
    # Impact
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "description": "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.",
        "detection": "Monitor for mass file deletion events; alert on cloud resource deletion operations; track bulk delete API calls in cloud environments.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
        "detection": "Monitor for ransomware-like file rename patterns (double extensions, known ransomware extensions); alert on ASR ransomware rule triggers; track mass file modification activity.",
    },
    "T1489": {
        "name": "Service Stop",
        "tactic": "Impact",
        "description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.",
        "detection": "Monitor for service stop commands targeting critical services (SQL, backup, AV); alert on batch service termination; track process kill commands targeting security tools.",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.",
        "detection": "Monitor for vssadmin/wmic shadowcopy delete commands; alert on BCDEdit modifications; track recovery service disablement.",
    },
    "T1491": {
        "name": "Defacement",
        "tactic": "Impact",
        "description": "Adversaries may modify visual content available internally or externally to an enterprise network.",
        "detection": "Monitor for unauthorized web content changes; alert on mass file modification in web directories; track integrity of public-facing content.",
    },
}

# ---------------------------------------------------------------------------
# Tactic -> Tactic ID mapping (for canonical naming)
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
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
}

# Normalized tactic slug for file naming
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
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resourcedevelopment",
}

# ---------------------------------------------------------------------------
# D3FEND Defensive Technique Mappings (by ATT&CK Tactic)
# ---------------------------------------------------------------------------
D3FEND_BY_TACTIC = {
    "Initial Access": {
        "techniques": [
            "Network Isolation (D3-NI): Restrict network exposure of services and limit inbound connectivity to essential paths only.",
            "Platform Hardening (D3-PH): Apply patches, disable unnecessary features, and enforce secure configurations on internet-facing systems.",
            "Credential Hardening (D3-CH): Enforce MFA on all external authentication; use phishing-resistant credentials (FIDO2/hardware tokens).",
            "Email Filtering (D3-EF): Deploy ATP email filtering to block malicious attachments and links before delivery to end users.",
        ],
        "primary": "Credential Hardening + Email Filtering + Platform Hardening",
    },
    "Execution": {
        "techniques": [
            "Application Hardening (D3-AH): Implement application allowlisting to prevent unauthorized code execution.",
            "Execution Isolation (D3-EI): Use containerization, sandboxing, and process isolation to limit execution scope.",
            "Script Execution Analysis (D3-SEA): Enable AMSI and Script Block Logging to analyze and block malicious scripts at runtime.",
            "Platform Monitoring (D3-PM): Monitor process creation events, command-line arguments, and parent-child process relationships.",
        ],
        "primary": "Application Hardening + Script Execution Analysis",
    },
    "Persistence": {
        "techniques": [
            "Platform Hardening (D3-PH): Restrict registry key modification permissions; disable unnecessary startup locations.",
            "Boot Record Integrity (D3-BRI): Monitor and enforce integrity of boot records and startup configurations.",
            "Account Management (D3-AM): Enforce JIT/just-enough-access provisioning; review and audit accounts regularly.",
            "Platform Monitoring (D3-PM): Monitor for new scheduled tasks, services, and autostart registry key modifications.",
        ],
        "primary": "Platform Monitoring + Account Management",
    },
    "Privilege Escalation": {
        "techniques": [
            "Credential Hardening (D3-CH): Use Privileged Access Workstations (PAW); enforce just-enough-access privilege model.",
            "Privilege Restriction (D3-PR): Implement least-privilege access; restrict local admin rights; use tiered admin model.",
            "User Account Control (D3-UAC): Enforce UAC for administrative operations; monitor elevation events.",
            "Platform Monitoring (D3-PM): Alert on token manipulation APIs; monitor sensitive group membership changes.",
        ],
        "primary": "Privilege Restriction + Credential Hardening",
    },
    "Defense Evasion": {
        "techniques": [
            "Platform Monitoring (D3-PM): Deploy EDR with behavioral detection; enable comprehensive process and file monitoring.",
            "Application Hardening (D3-AH): Block unsigned script execution; enforce WDAC/AppLocker policies.",
            "Endpoint Health Beacon (D3-EHB): Monitor security tool health status; alert on defensive tool tampering.",
            "Log Analysis (D3-LA): Centralize and protect log infrastructure; implement immutable logging.",
        ],
        "primary": "Platform Monitoring + Endpoint Health Beacon",
    },
    "Credential Access": {
        "techniques": [
            "Credential Hardening (D3-CH): Enable Windows Credential Guard; use gMSA for service accounts; enforce strong password policies.",
            "Multi-Factor Authentication (D3-MFA): Deploy phishing-resistant MFA (FIDO2) for all privileged accounts.",
            "Credential Vault Management (D3-CVM): Use PAM solutions (CyberArk, Azure Key Vault); rotate credentials regularly.",
            "Platform Monitoring (D3-PM): Monitor LSASS access; alert on credential dumping tool patterns; track authentication anomalies.",
        ],
        "primary": "Multi-Factor Authentication + Credential Hardening",
    },
    "Discovery": {
        "techniques": [
            "Network Isolation (D3-NI): Segment networks to limit lateral visibility; implement zero-trust network architecture.",
            "User Account Management (D3-UAM): Restrict enumeration rights; limit who can query directory services.",
            "Platform Monitoring (D3-PM): Alert on anomalous enumeration commands; monitor LDAP query volumes.",
            "Access Control (D3-AC): Implement RBAC; restrict access to directory enumeration APIs.",
        ],
        "primary": "Network Isolation + Platform Monitoring",
    },
    "Lateral Movement": {
        "techniques": [
            "Network Isolation (D3-NI): Implement micro-segmentation; restrict SMB/WMI/RDP between workstations.",
            "Credential Hardening (D3-CH): Eliminate credential reuse; deploy LAPS for local admin accounts; use tiered admin model.",
            "Protocol Isolation (D3-PI): Block unnecessary lateral movement protocols at host-based firewall level.",
            "Platform Monitoring (D3-PM): Monitor remote authentication events; alert on admin share access patterns.",
        ],
        "primary": "Network Isolation + Credential Hardening",
    },
    "Collection": {
        "techniques": [
            "Data Loss Prevention (D3-DLP): Deploy DLP to detect and block sensitive data collection attempts.",
            "File Encryption (D3-FE): Encrypt sensitive data at rest to limit value of collected information.",
            "Access Control (D3-AC): Restrict access to sensitive data repositories; implement need-to-know access controls.",
            "Platform Monitoring (D3-PM): Monitor bulk file access and email forwarding rule creation.",
        ],
        "primary": "Data Loss Prevention + Access Control",
    },
    "Command and Control": {
        "techniques": [
            "Network Traffic Analysis (D3-NTA): Deploy NDR/NTA solutions to detect C2 beaconing and anomalous outbound connections.",
            "DNS Allowlisting (D3-DAL): Implement DNS sinkholes and allowlisting to block C2 domain resolution.",
            "Port Restriction (D3-PR): Block outbound connections to non-approved ports and protocols.",
            "Protocol Analysis (D3-PA): Inspect application layer protocols for C2 characteristics (beaconing, encrypted channels).",
        ],
        "primary": "Network Traffic Analysis + DNS Allowlisting",
    },
    "Exfiltration": {
        "techniques": [
            "Network Traffic Analysis (D3-NTA): Monitor for large or unusual outbound data transfers; detect protocol anomalies.",
            "Data Loss Prevention (D3-DLP): Implement DLP to detect and block sensitive data leaving the organization.",
            "Protocol Allowlisting (D3-PAL): Restrict outbound protocols to known-good; block unusual exfiltration channels (DNS, ICMP tunneling).",
            "Endpoint Monitoring (D3-EM): Monitor for data staging and compression utilities used for exfiltration preparation.",
        ],
        "primary": "Data Loss Prevention + Network Traffic Analysis",
    },
    "Impact": {
        "techniques": [
            "Backup (D3-B): Maintain offline, immutable backups tested regularly for restoration capability.",
            "Data Recovery (D3-DR): Implement and test incident recovery procedures; use versioned storage.",
            "Service Hardening (D3-SH): Restrict which processes can stop critical services; implement service integrity monitoring.",
            "Platform Monitoring (D3-PM): Alert on shadow copy deletion, mass file modification, and service termination events.",
        ],
        "primary": "Backup + Service Hardening",
    },
}

# ---------------------------------------------------------------------------
# Tactic color palette for Excel formatting
# ---------------------------------------------------------------------------
TACTIC_COLORS = {
    "Initial Access":      "FF4C6EF5",  # Blue
    "Execution":           "FFFA8231",  # Orange
    "Persistence":         "FF20C997",  # Teal
    "Privilege Escalation":"FFAE3EC9",  # Purple
    "Defense Evasion":     "FFFD7E14",  # Amber
    "Credential Access":   "FFFA5252",  # Red
    "Discovery":           "FF4DABF7",  # Light Blue
    "Lateral Movement":    "FF339AF0",  # Sky Blue
    "Collection":          "FF94D82D",  # Green
    "Command and Control": "FFE64980",  # Pink
    "Exfiltration":        "FFFF6B6B",  # Coral
    "Impact":              "FFE03131",  # Dark Red
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def slugify(text):
    """Create a filesystem-safe slug from a string."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\-]", "", text.replace(" ", "-"))
    text = re.sub(r"-+", "-", text).strip("-")
    return text


def extract_title(content):
    """Extract the first H1 heading as the query title."""
    m = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    return m.group(1).strip() if m else ""


def extract_description(content):
    """Extract the Description section from the markdown file."""
    m = re.search(
        r"####\s+Description\s*\n(.*?)(?=\n####|\n##|\Z)",
        content,
        re.DOTALL | re.IGNORECASE,
    )
    if m:
        desc = m.group(1).strip()
        return desc[:500] + "…" if len(desc) > 500 else desc
    return ""


def extract_risk(content):
    """Extract the Risk section."""
    m = re.search(
        r"####\s+Risk\s*\n(.*?)(?=\n####|\n##|\Z)",
        content,
        re.DOTALL | re.IGNORECASE,
    )
    if m:
        risk = m.group(1).strip()
        return risk[:400] + "…" if len(risk) > 400 else risk
    return ""


def extract_platforms(content):
    """Return list of platforms that have a KQL block."""
    platforms = []
    for name in ["Defender For Endpoint", "Sentinel", "Defender For Identity",
                 "Defender For Cloud Apps", "Graph API", "Azure Active Directory",
                 "Defender XDR", "Log Analytics"]:
        if re.search(r"##\s+" + re.escape(name), content, re.IGNORECASE):
            platforms.append(name)
    return platforms if platforms else ["Unknown"]


def extract_technique_ids(content):
    """Extract MITRE technique IDs from the file content."""
    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", content, re.IGNORECASE)
    return list(dict.fromkeys(id_.upper() for id_ in ids))


def read_file_safe(path):
    for enc in ("utf-8", "latin-1"):
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue
    return ""


# ---------------------------------------------------------------------------
# Parse Mapping.md → list of {technique_id, tactic, title, rel_path}
# ---------------------------------------------------------------------------

def parse_mapping_md(mapping_path):
    """Parse the central Mapping.md and return list of query-technique records."""
    content = read_file_safe(mapping_path)
    entries = []
    current_tactic = "Unknown"

    for line in content.splitlines():
        # Detect tactic headers (## Tactic Name)
        h2 = re.match(r"^##\s+(.+)$", line)
        if h2:
            current_tactic = h2.group(1).strip()
            continue

        # Detect table rows: | T1234 | Title | [Query](path) |
        row = re.match(r"^\|\s*(T\d{4}(?:\.\d{3})?)\s*\|(.+?)\|(.+?)\|", line)
        if not row:
            continue

        tech_id = row.group(1).strip().upper()
        tech_title = row.group(2).strip()
        link_cell = row.group(3).strip()

        # Extract display text and relative path from markdown link
        link_m = re.search(r"\[(.+?)\]\((.+?)\)", link_cell)
        if not link_m:
            continue

        query_title = link_m.group(1).strip()
        rel_path = link_m.group(2).strip()
        # URL-decode
        rel_path = rel_path.replace("%20", " ").replace("%26", "&")

        entries.append({
            "tactic": current_tactic,
            "technique_id": tech_id,
            "technique_name": tech_title,
            "query_title": query_title,
            "rel_path": rel_path,
        })

    return entries


# ---------------------------------------------------------------------------
# Build full record for each entry
# ---------------------------------------------------------------------------

def build_record(entry, repo_root):
    tech_id = entry["technique_id"]
    tactic = entry["tactic"]

    # Resolve file path from the relative link in Mapping.md
    mapping_dir = repo_root / "MITRE ATT&CK"
    raw_path = (mapping_dir / entry["rel_path"]).resolve()

    # Try with and without .md extension
    file_path = None
    for candidate in [raw_path, Path(str(raw_path) + ".md")]:
        if candidate.exists():
            file_path = candidate
            break

    content = read_file_safe(file_path) if file_path else ""

    # MITRE technique knowledge
    tech_info = ATTACK_TECHNIQUES.get(tech_id, {})
    if not tech_info:
        # Try parent technique (e.g., T1566.001 → T1566)
        parent_id = tech_id.split(".")[0] if "." in tech_id else None
        tech_info = ATTACK_TECHNIQUES.get(parent_id, {}) if parent_id else {}

    technique_description = tech_info.get(
        "description",
        f"See https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
    )
    detection_strategy = tech_info.get(
        "detection",
        "Monitor relevant logs and telemetry for anomalous activity associated with this technique.",
    )

    # D3FEND
    d3fend_info = D3FEND_BY_TACTIC.get(tactic, {})
    d3fend_primary = d3fend_info.get("primary", "Platform Monitoring + Access Control")
    d3fend_detail = "\n".join(d3fend_info.get("techniques", [
        "Platform Monitoring (D3-PM): Monitor for anomalous system and network activity.",
        "Access Control (D3-AC): Apply least-privilege principles to limit attack surface.",
    ]))

    # Platforms from file
    platforms = extract_platforms(content) if content else ["Unknown"]

    # Description and risk from file
    query_description = extract_description(content) or ""
    query_risk = extract_risk(content) or ""

    # Build canonical name: tactic-slug + query-slug
    tactic_slug = TACTIC_SLUG.get(tactic, slugify(tactic))
    query_slug = slugify(entry["query_title"])
    canonical_name = f"{tactic_slug}-{query_slug}"

    # ATT&CK technique URL
    tech_url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"

    # D3FEND URL (tactic-level)
    d3fend_url = "https://d3fend.mitre.org/"

    # Relative file path for display
    rel_display = str(file_path.relative_to(repo_root)) if file_path else entry["rel_path"]

    return {
        "Canonical Name": canonical_name,
        "Query Title": entry["query_title"],
        "MITRE Tactic": tactic,
        "Tactic ID": TACTIC_IDS.get(tactic, ""),
        "Technique ID": tech_id,
        "Technique Name": entry["technique_name"],
        "Technique Description": technique_description,
        "ATT&CK Technique URL": tech_url,
        "Detection Strategy (ATT&CK)": detection_strategy,
        "D3FEND Primary Strategy": d3fend_primary,
        "D3FEND Defensive Techniques": d3fend_detail,
        "D3FEND URL": d3fend_url,
        "Platforms": ", ".join(platforms),
        "Query Description": query_description,
        "Risk": query_risk,
        "File Path": rel_display,
    }


# ---------------------------------------------------------------------------
# Excel generation
# ---------------------------------------------------------------------------

COLUMNS = [
    "Canonical Name",
    "Query Title",
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
    "Query Title": 45,
    "MITRE Tactic": 22,
    "Tactic ID": 12,
    "Technique ID": 14,
    "Technique Name": 45,
    "Technique Description": 70,
    "ATT&CK Technique URL": 55,
    "Detection Strategy (ATT&CK)": 70,
    "D3FEND Primary Strategy": 45,
    "D3FEND Defensive Techniques": 80,
    "D3FEND URL": 35,
    "Platforms": 40,
    "Query Description": 70,
    "Risk": 55,
    "File Path": 60,
}


def make_border():
    thin = Side(style="thin", color="FFD0D0D0")
    return Border(left=thin, right=thin, top=thin, bottom=thin)


def write_excel(records, output_path):
    wb = openpyxl.Workbook()

    # ---- Summary sheet ----
    ws_sum = wb.active
    ws_sum.title = "Summary"

    # Header
    ws_sum["A1"] = "MITRE ATT&CK Detection & D3FEND Mapping"
    ws_sum["A1"].font = Font(name="Calibri", size=18, bold=True, color="FF2F4F8F")
    ws_sum["A2"] = f"Repository: Hunting-Queries-Detection-Rules"
    ws_sum["A3"] = f"Total Mapped Queries: {len(records)}"
    ws_sum["A4"] = "Generated by: MITRE ATT&CK Excel Mapping Generator"

    # Tactic stats
    from collections import Counter
    tactic_counts = Counter(r["MITRE Tactic"] for r in records)

    ws_sum["A6"] = "Tactic"
    ws_sum["B6"] = "Query Count"
    ws_sum["A6"].font = Font(bold=True, color="FFFFFFFF")
    ws_sum["B6"].font = Font(bold=True, color="FFFFFFFF")
    ws_sum["A6"].fill = PatternFill("solid", fgColor="FF2F4F8F")
    ws_sum["B6"].fill = PatternFill("solid", fgColor="FF2F4F8F")

    for i, (tactic, count) in enumerate(sorted(tactic_counts.items()), start=7):
        ws_sum.cell(row=i, column=1, value=tactic)
        ws_sum.cell(row=i, column=2, value=count)
        color = TACTIC_COLORS.get(tactic, "FFEEEEEE")[2:]  # strip "FF" alpha prefix
        ws_sum.cell(row=i, column=1).fill = PatternFill("solid", fgColor=color)
        ws_sum.cell(row=i, column=1).font = Font(color="FFFFFFFF", bold=True)

    ws_sum.column_dimensions["A"].width = 28
    ws_sum.column_dimensions["B"].width = 16

    # ---- Main mapping sheet ----
    ws = wb.create_sheet(title="ATT&CK Mapping")

    # Write header row
    header_fill = PatternFill("solid", fgColor="FF2F4F8F")
    header_font = Font(name="Calibri", bold=True, color="FFFFFFFF", size=11)
    header_align = Alignment(horizontal="center", vertical="center", wrap_text=True)

    for col_idx, col_name in enumerate(COLUMNS, start=1):
        cell = ws.cell(row=1, column=col_idx, value=col_name)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = header_align
        cell.border = make_border()

    ws.row_dimensions[1].height = 30

    # Write data rows
    wrap = Alignment(vertical="top", wrap_text=True)
    for row_idx, record in enumerate(records, start=2):
        tactic = record.get("MITRE Tactic", "")
        row_color = TACTIC_COLORS.get(tactic, "FFEEEEEE")

        for col_idx, col_name in enumerate(COLUMNS, start=1):
            val = record.get(col_name, "")
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.alignment = wrap
            cell.border = make_border()

            # Shade alternating rows with tactic color (lighter for non-first columns)
            if col_idx == 3:  # MITRE Tactic column gets full color
                cell.fill = PatternFill("solid", fgColor=row_color)
                cell.font = Font(color="FFFFFFFF", bold=True)
            elif row_idx % 2 == 0:
                cell.fill = PatternFill("solid", fgColor="FFF8F9FA")

    # Freeze header row
    ws.freeze_panes = "A2"

    # Set column widths
    for col_idx, col_name in enumerate(COLUMNS, start=1):
        ws.column_dimensions[get_column_letter(col_idx)].width = COLUMN_WIDTHS.get(col_name, 30)

    # Auto-filter
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}1"

    # ---- Per-tactic sheets ----
    from collections import defaultdict
    by_tactic = defaultdict(list)
    for r in records:
        by_tactic[r["MITRE Tactic"]].append(r)

    tactic_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    ]

    for tactic in tactic_order:
        tactic_records = by_tactic.get(tactic, [])
        if not tactic_records:
            continue

        # Sheet name max 31 chars
        sheet_name = tactic[:31]
        ws_t = wb.create_sheet(title=sheet_name)

        # Tactic header banner
        tac_color = TACTIC_COLORS.get(tactic, "FF444444")
        ws_t.merge_cells("A1:P1")
        banner = ws_t["A1"]
        banner.value = f"MITRE ATT&CK Tactic: {tactic}  |  {TACTIC_IDS.get(tactic, '')}  |  Query Count: {len(tactic_records)}"
        banner.font = Font(name="Calibri", size=14, bold=True, color="FFFFFFFF")
        banner.fill = PatternFill("solid", fgColor=tac_color)
        banner.alignment = Alignment(horizontal="center", vertical="center")
        ws_t.row_dimensions[1].height = 28

        # D3FEND section below banner
        d3fend_info = D3FEND_BY_TACTIC.get(tactic, {})
        ws_t.merge_cells("A2:P2")
        d3_cell = ws_t["A2"]
        d3_cell.value = f"D3FEND Primary Defense: {d3fend_info.get('primary', 'See d3fend.mitre.org')}"
        d3_cell.font = Font(bold=True, color="FF2F4F8F")
        d3_cell.alignment = Alignment(horizontal="left", vertical="center")
        ws_t.row_dimensions[2].height = 20

        # Column headers on row 3
        for col_idx, col_name in enumerate(COLUMNS, start=1):
            cell = ws_t.cell(row=3, column=col_idx, value=col_name)
            cell.fill = PatternFill("solid", fgColor=tac_color)
            cell.font = Font(bold=True, color="FFFFFFFF")
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = make_border()
        ws_t.row_dimensions[3].height = 28

        # Data rows starting at row 4
        for row_idx, record in enumerate(tactic_records, start=4):
            for col_idx, col_name in enumerate(COLUMNS, start=1):
                val = record.get(col_name, "")
                cell = ws_t.cell(row=row_idx, column=col_idx, value=val)
                cell.alignment = Alignment(vertical="top", wrap_text=True)
                cell.border = make_border()
                if row_idx % 2 == 0:
                    cell.fill = PatternFill("solid", fgColor="FFF8F9FA")

        ws_t.freeze_panes = "A4"
        ws_t.auto_filter.ref = f"A3:{get_column_letter(len(COLUMNS))}3"

        for col_idx, col_name in enumerate(COLUMNS, start=1):
            ws_t.column_dimensions[get_column_letter(col_idx)].width = COLUMN_WIDTHS.get(col_name, 30)

    wb.save(output_path)
    print(f"\nExcel file saved: {output_path}")
    print(f"Total records: {len(records)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    repo_root = Path(__file__).parent.parent.resolve()
    mapping_path = repo_root / "MITRE ATT&CK" / "Mapping.md"

    print(f"Repository root: {repo_root}")
    print(f"Parsing Mapping.md from: {mapping_path}")

    entries = parse_mapping_md(mapping_path)
    print(f"Found {len(entries)} query-technique entries in Mapping.md")

    records = []
    for entry in entries:
        try:
            rec = build_record(entry, repo_root)
            records.append(rec)
        except Exception as exc:
            print(f"  WARN: skipping entry {entry.get('query_title')!r}: {exc}")

    # Sort by tactic order then technique ID
    tactic_order_map = {t: i for i, t in enumerate([
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    ])}
    records.sort(key=lambda r: (
        tactic_order_map.get(r["MITRE Tactic"], 99),
        r["Technique ID"],
        r["Query Title"],
    ))

    output_path = repo_root / "MITRE ATT&CK" / "MITRE_ATT&CK_Detection_D3FEND_Mapping.xlsx"
    write_excel(records, output_path)


if __name__ == "__main__":
    main()
