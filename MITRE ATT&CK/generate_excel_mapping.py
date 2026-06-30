#!/usr/bin/env python3
"""
MITRE ATT&CK Excel Mapping Generator
- Scans every detection query .md file in the repository
- Extracts KQL query code (MDE preferred, Sentinel fallback)
- Uses explicit MITRE table if present; otherwise infers technique
  from file name, folder, description, and query content
- Generates a fully formatted Excel workbook with ATT&CK + D3FEND mapping
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

# ============================================================
# MITRE ATT&CK Technique Knowledge Base
# ============================================================
ATTACK_TECHNIQUES = {
    "T1003":     {"name": "OS Credential Dumping",                             "tactic": "Credential Access",    "description": "Adversaries attempt to dump credentials to obtain account login material, hashes, or cleartext passwords.", "detection": "Monitor LSASS process access; alert on NTDS.dit file access and credential dumping tools."},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory",               "tactic": "Credential Access",    "description": "Adversaries access credential material stored in LSASS process memory.",                               "detection": "Monitor for LSASS memory access; alert on procdump.exe targeting LSASS; enable Credential Guard."},
    "T1003.003": {"name": "OS Credential Dumping: NTDS",                       "tactic": "Credential Access",    "description": "Adversaries access or copy the Active Directory domain database to steal credential hashes.",            "detection": "Monitor ntds.dit file access and shadow copy creation on domain controllers."},
    "T1018":     {"name": "Remote System Discovery",                            "tactic": "Discovery",            "description": "Adversaries enumerate other systems by IP, hostname, or logical identifier for lateral movement prep.",    "detection": "Monitor network scanning; alert on unusual SMB session creation; track net view commands."},
    "T1021":     {"name": "Remote Services",                                    "tactic": "Lateral Movement",     "description": "Adversaries use Valid Accounts to log into services that accept remote connections.",                    "detection": "Monitor remote service authentication; alert on lateral movement patterns."},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol",           "tactic": "Lateral Movement",     "description": "Adversaries use RDP to access systems remotely.",                                                      "detection": "Monitor RDP logins; alert on RDP from unexpected sources; track session creation events."},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares",         "tactic": "Lateral Movement",     "description": "Adversaries interact with remote network shares using SMB.",                                            "detection": "Monitor SMB file copy events; alert on admin share access from unusual hosts."},
    "T1027":     {"name": "Obfuscated Files or Information",                    "tactic": "Defense Evasion",      "description": "Adversaries encode or obfuscate executables and files to evade detection.",                              "detection": "Enable AMSI and Script Block Logging; monitor encoded PowerShell commands and high-entropy strings."},
    "T1027.010": {"name": "Obfuscated Files or Information: Command Obfuscation","tactic": "Defense Evasion",     "description": "Adversaries obfuscate command-line content to impede detection.",                                        "detection": "Monitor for unusual character substitutions and concatenation in command lines."},
    "T1033":     {"name": "System Owner/User Discovery",                        "tactic": "Discovery",            "description": "Adversaries attempt to find the primary user, current user, or set of users on a system.",              "detection": "Monitor for whoami, query user, and similar reconnaissance commands."},
    "T1040":     {"name": "Network Sniffing",                                   "tactic": "Discovery",            "description": "Adversaries sniff network traffic to capture information including authentication material.",             "detection": "Monitor for promiscuous mode; alert on network capture tools (Wireshark, tcpdump, netsh trace)."},
    "T1046":     {"name": "Network Service Discovery",                          "tactic": "Discovery",            "description": "Adversaries enumerate services running on remote hosts and network devices.",                            "detection": "Monitor for port scanning activity; alert on nmap-like patterns; track service discovery commands."},
    "T1047":     {"name": "Windows Management Instrumentation",                 "tactic": "Execution",            "description": "Adversaries abuse WMI to execute commands and scripts.",                                               "detection": "Monitor WMI activity; log wmiprvse.exe spawning child processes; alert on remote WMI invocations."},
    "T1048":     {"name": "Exfiltration Over Alternative Protocol",             "tactic": "Exfiltration",         "description": "Adversaries exfiltrate data over a different protocol than the C2 channel.",                            "detection": "Monitor for unusual outbound protocol usage; alert on large data transfers over DNS, ICMP, or non-standard channels."},
    "T1053":     {"name": "Scheduled Task/Job",                                 "tactic": "Persistence",          "description": "Adversaries abuse task scheduling to execute malicious code.",                                          "detection": "Monitor for scheduled task creation (Event ID 4698); audit new tasks and their execution paths."},
    "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task",                 "tactic": "Persistence",          "description": "Adversaries abuse Windows Task Scheduler to execute programs at system startup or on a schedule.",      "detection": "Monitor Event ID 4698 for task creation; audit schtasks.exe command-line arguments."},
    "T1055":     {"name": "Process Injection",                                  "tactic": "Defense Evasion",      "description": "Adversaries inject code into running processes to evade detection and escalate privileges.",             "detection": "Monitor for unusual cross-process memory access; alert on CreateRemoteThread and VirtualAllocEx API calls."},
    "T1059":     {"name": "Command and Scripting Interpreter",                  "tactic": "Execution",            "description": "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries.",          "detection": "Monitor process creation for scripting interpreters; log command-line arguments."},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell",      "tactic": "Execution",            "description": "Adversaries abuse PowerShell commands and scripts for execution.",                                      "detection": "Enable PowerShell Script Block Logging (Event 4104); monitor for encoded commands and AMSI bypass."},
    "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell","tactic": "Execution",       "description": "Adversaries abuse the Windows command shell (cmd.exe) to execute commands.",                           "detection": "Monitor cmd.exe process creation; alert on cmd spawned by Office apps or webservers."},
    "T1069":     {"name": "Permission Groups Discovery",                        "tactic": "Discovery",            "description": "Adversaries discover group and permission settings.",                                                   "detection": "Monitor for net group/localgroup commands; alert on LDAP group membership queries."},
    "T1069.001": {"name": "Permission Groups Discovery: Local Groups",          "tactic": "Discovery",            "description": "Adversaries discover local system groups and permission settings.",                                     "detection": "Monitor for net localgroup commands; alert on unusual local group enumeration."},
    "T1069.003": {"name": "Permission Groups Discovery: Cloud Groups",          "tactic": "Discovery",            "description": "Adversaries discover cloud groups and permission settings.",                                           "detection": "Monitor Azure AD audit logs for bulk group membership queries; alert on AzureHound-like patterns."},
    "T1071":     {"name": "Application Layer Protocol",                         "tactic": "Command and Control",  "description": "Adversaries communicate using OSI application layer protocols to blend in with existing traffic.",      "detection": "Monitor for unusual application layer protocol usage; analyze network flows for C2 beaconing."},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols",          "tactic": "Command and Control",  "description": "Adversaries communicate using HTTP/HTTPS to blend in with legitimate traffic.",                         "detection": "Monitor for C2 beaconing patterns in HTTP/HTTPS; alert on Telegram API or unusual cloud services for C2."},
    "T1078":     {"name": "Valid Accounts",                                     "tactic": "Initial Access",       "description": "Adversaries obtain and abuse credentials of existing accounts to gain access.",                        "detection": "Monitor for suspicious account access, impossible travel, and unusual login times/locations."},
    "T1078.002": {"name": "Valid Accounts: Domain Accounts",                    "tactic": "Privilege Escalation", "description": "Adversaries obtain and abuse credentials of a domain account with broad access.",                       "detection": "Monitor for anomalous domain account use; track privileged group membership changes."},
    "T1078.004": {"name": "Valid Accounts: Cloud Accounts",                     "tactic": "Initial Access",       "description": "Adversaries obtain and abuse credentials of a cloud account.",                                        "detection": "Monitor Azure AD sign-in logs for impossible travel, anomalous app access, failed MFA prompts."},
    "T1082":     {"name": "System Information Discovery",                       "tactic": "Discovery",            "description": "Adversaries attempt to get detailed information about the operating system and hardware.",              "detection": "Monitor for systeminfo, hostname, and similar system reconnaissance commands."},
    "T1087":     {"name": "Account Discovery",                                  "tactic": "Discovery",            "description": "Adversaries attempt to get a listing of accounts on a system or environment.",                         "detection": "Monitor for net user/localgroup commands; alert on LDAP enumeration."},
    "T1087.002": {"name": "Account Discovery: Domain Account",                  "tactic": "Discovery",            "description": "Adversaries attempt to get a listing of domain accounts.",                                            "detection": "Monitor for unusual LDAP queries; alert on BloodHound/SharpHound-like enumeration patterns."},
    "T1087.004": {"name": "Account Discovery: Cloud Account",                   "tactic": "Discovery",            "description": "Adversaries attempt to get a listing of cloud accounts.",                                            "detection": "Monitor Azure AD logs; alert on bulk user download operations."},
    "T1090":     {"name": "Proxy",                                              "tactic": "Command and Control",  "description": "Adversaries use a connection proxy to direct network traffic.",                                         "detection": "Monitor for proxy usage from unexpected endpoints; alert on anonymous proxy/VPN usage."},
    "T1091":     {"name": "Replication Through Removable Media",                "tactic": "Initial Access",       "description": "Adversaries move onto systems via copying malware to removable media.",                                "detection": "Monitor USB device connections; alert on executables launched from removable media."},
    "T1098":     {"name": "Account Manipulation",                               "tactic": "Persistence",          "description": "Adversaries manipulate accounts to maintain access to victim systems.",                                 "detection": "Monitor for account changes: password resets, permission modifications, MFA changes, OAuth grants."},
    "T1098.001": {"name": "Account Manipulation: Additional Cloud Credentials", "tactic": "Persistence",          "description": "Adversaries add credentials to cloud accounts to maintain persistent access.",                          "detection": "Monitor Azure AD audit logs for credential additions to service principals."},
    "T1105":     {"name": "Ingress Tool Transfer",                              "tactic": "Command and Control",  "description": "Adversaries transfer tools from external systems into a compromised environment.",                      "detection": "Monitor for certutil/bitsadmin/curl download patterns; alert on LOLBin-based file downloads."},
    "T1110":     {"name": "Brute Force",                                        "tactic": "Credential Access",    "description": "Adversaries use brute force techniques to gain access to accounts.",                                   "detection": "Monitor for multiple failed authentication attempts; alert on account lockouts across multiple accounts."},
    "T1114":     {"name": "Email Collection",                                   "tactic": "Collection",           "description": "Adversaries target user email to collect sensitive information.",                                      "detection": "Monitor email access patterns; alert on bulk email downloads or forwarding rules."},
    "T1127.001": {"name": "Trusted Developer Utilities Proxy Execution: MSBuild","tactic": "Defense Evasion",     "description": "Adversaries use MSBuild to proxy execution of code through a trusted Windows utility.",                 "detection": "Monitor MSBuild.exe for network connections and unusual child processes."},
    "T1134":     {"name": "Access Token Manipulation",                          "tactic": "Privilege Escalation", "description": "Adversaries modify access tokens to operate under a different security context.",                       "detection": "Monitor for token manipulation APIs; alert on RunAs usage with saved credentials."},
    "T1134.002": {"name": "Access Token Manipulation: Create Process with Token","tactic": "Privilege Escalation","description": "Adversaries create a new process with an existing token to escalate privileges.",                      "detection": "Monitor for runas.exe with /savecred; track processes spawning with different user context."},
    "T1136":     {"name": "Create Account",                                     "tactic": "Persistence",          "description": "Adversaries create an account to maintain access to victim systems.",                                  "detection": "Monitor for account creation events; alert on accounts created outside provisioning workflows."},
    "T1136.001": {"name": "Create Account: Local Account",                      "tactic": "Persistence",          "description": "Adversaries create a local account to maintain access.",                                              "detection": "Monitor Windows Event ID 4720; alert on net user /add commands."},
    "T1136.002": {"name": "Create Account: Domain Account",                     "tactic": "Persistence",          "description": "Adversaries create a domain account to maintain access.",                                             "detection": "Monitor AD event ID 4720; alert on accounts created via command line."},
    "T1136.003": {"name": "Create Account: Cloud Account",                      "tactic": "Persistence",          "description": "Adversaries create a cloud account to maintain access.",                                             "detection": "Monitor Azure AD audit logs for user creation; alert on accounts that immediately receive elevated roles."},
    "T1137":     {"name": "Office Application Startup",                         "tactic": "Persistence",          "description": "Adversaries leverage Microsoft Office applications for persistence.",                                   "detection": "Monitor for Office add-ins and COM objects; alert on executable content launched by Office."},
    "T1190":     {"name": "Exploit Public-Facing Application",                  "tactic": "Initial Access",       "description": "Adversaries exploit weaknesses in Internet-facing hosts to gain access.",                              "detection": "Monitor application logs for exploitation attempts; alert on CVEs matching internet-exposed assets."},
    "T1201":     {"name": "Password Policy Discovery",                          "tactic": "Discovery",            "description": "Adversaries access information about password policies.",                                              "detection": "Monitor for net accounts commands; alert on LDAP queries for password policy objects."},
    "T1218":     {"name": "System Binary Proxy Execution",                      "tactic": "Defense Evasion",      "description": "Adversaries use signed binaries to proxy execution of malicious content.",                             "detection": "Monitor LOLBins for unusual arguments or network activity."},
    "T1218.010": {"name": "System Binary Proxy Execution: Regsvr32",            "tactic": "Defense Evasion",      "description": "Adversaries abuse Regsvr32.exe to proxy execution of malicious code.",                                "detection": "Monitor regsvr32.exe spawned by Office or from temp directories."},
    "T1219":     {"name": "Remote Access Software",                             "tactic": "Command and Control",  "description": "Adversaries use legitimate remote access software such as AnyDesk and TeamViewer.",                   "detection": "Monitor for unapproved remote access tools; alert on RAT/RMM installations; track unexpected connections."},
    "T1484":     {"name": "Domain Policy Modification",                         "tactic": "Privilege Escalation", "description": "Adversaries modify domain configuration settings to evade defenses or escalate privileges.",            "detection": "Monitor Group Policy Object modifications; alert on changes to domain trust settings."},
    "T1484.001": {"name": "Domain Policy Modification: Group Policy Modification","tactic": "Privilege Escalation","description": "Adversaries modify Group Policy Objects to subvert access controls or escalate privileges.",          "detection": "Monitor GPO change events; alert on unauthorized policy modifications."},
    "T1485":     {"name": "Data Destruction",                                   "tactic": "Impact",               "description": "Adversaries destroy data and files to interrupt availability.",                                        "detection": "Monitor for mass file deletion events; alert on cloud resource deletion operations."},
    "T1486":     {"name": "Data Encrypted for Impact",                          "tactic": "Impact",               "description": "Adversaries encrypt data on target systems to interrupt availability.",                                "detection": "Monitor for ransomware file rename patterns; alert on ASR ransomware rule triggers."},
    "T1489":     {"name": "Service Stop",                                       "tactic": "Impact",               "description": "Adversaries stop or disable services to render them unavailable.",                                    "detection": "Monitor for service stop commands targeting critical services; alert on batch service termination."},
    "T1490":     {"name": "Inhibit System Recovery",                            "tactic": "Impact",               "description": "Adversaries delete or disable built-in recovery data to prevent system recovery.",                   "detection": "Monitor for vssadmin/wmic shadowcopy delete commands; alert on BCDEdit modifications."},
    "T1505.003": {"name": "Server Software Component: Web Shell",               "tactic": "Persistence",          "description": "Adversaries backdoor web servers with web shells to establish persistent access.",                      "detection": "Monitor web server logs for unusual POST requests; alert on new executables in web directories."},
    "T1518.001": {"name": "Software Discovery: Security Software Discovery",    "tactic": "Discovery",            "description": "Adversaries enumerate security software configurations installed on a system.",                        "detection": "Monitor WMIC queries targeting antivirus/security products; alert on Defender enumeration."},
    "T1543":     {"name": "Create or Modify System Process",                    "tactic": "Persistence",          "description": "Adversaries create or modify system processes to execute malicious payloads persistently.",            "detection": "Monitor for new services or modified service configurations."},
    "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys","tactic": "Persistence",         "description": "Adversaries add programs to Run keys or startup folder for persistence.",                            "detection": "Monitor registry modifications to HKCU/HKLM Run keys; alert on new startup folder entries."},
    "T1548.003": {"name": "Abuse Elevation Control Mechanism: Sudo",            "tactic": "Privilege Escalation", "description": "Adversaries perform sudo caching or use sudoers file to elevate privileges.",                          "detection": "Monitor /etc/sudoers modifications; alert on users added to sudo group."},
    "T1552":     {"name": "Unsecured Credentials",                              "tactic": "Credential Access",    "description": "Adversaries search compromised systems for insecurely stored credentials.",                           "detection": "Monitor command-line activity for credential strings; alert on processes reading credential files."},
    "T1553.005": {"name": "Subvert Trust Controls: Mark-of-the-Web Bypass",    "tactic": "Defense Evasion",      "description": "Adversaries abuse file formats to subvert Mark-of-the-Web controls (ISO, VHD).",                     "detection": "Monitor for mounting of ISO/VHD/IMG files; alert on processes launched from mounted containers."},
    "T1556":     {"name": "Modify Authentication Process",                      "tactic": "Persistence",          "description": "Adversaries modify authentication mechanisms to access credentials or enable unauthorized access.",    "detection": "Monitor for changes to authentication configuration; alert on conditional access policy modifications."},
    "T1557":     {"name": "Adversary-in-the-Middle",                            "tactic": "Credential Access",    "description": "Adversaries position themselves between networked devices to intercept communications.",              "detection": "Monitor for AiTM phishing patterns; alert on session cookie theft; track impossible travel."},
    "T1558.003": {"name": "Steal or Forge Kerberos Tickets: Kerberoasting",     "tactic": "Credential Access",    "description": "Adversaries abuse Kerberos to obtain TGS tickets for offline password cracking.",                    "detection": "Monitor for TGS ticket requests for unusual SPNs; alert on RC4 downgrade in Kerberos TGS."},
    "T1562":     {"name": "Impair Defenses",                                    "tactic": "Defense Evasion",      "description": "Adversaries modify victim environment components to hinder defensive mechanisms.",                     "detection": "Monitor security product status changes; alert on antivirus/EDR disablement."},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools",           "tactic": "Defense Evasion",      "description": "Adversaries disable or modify security tools to avoid detection.",                                    "detection": "Monitor for Defender disablement via PowerShell (Set-MpPreference); alert on EDR offboarding downloads."},
    "T1562.010": {"name": "Impair Defenses: Downgrade Attack",                  "tactic": "Defense Evasion",      "description": "Adversaries downgrade system features to versions without updated security controls.",                "detection": "Monitor Kerberos encryption type negotiations; alert on RC4 usage in AES-configured environments."},
    "T1566":     {"name": "Phishing",                                           "tactic": "Initial Access",       "description": "Adversaries send phishing messages to gain access to victim systems.",                               "detection": "Monitor email gateway logs for suspicious attachments/links; correlate email delivery with endpoint events."},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment",                 "tactic": "Initial Access",       "description": "Adversaries send spearphishing emails with malicious attachments.",                                  "detection": "Monitor for suspicious email attachments (macros, executables, ISO); correlate with process creation."},
    "T1566.002": {"name": "Phishing: Spearphishing Link",                       "tactic": "Initial Access",       "description": "Adversaries send spearphishing emails with malicious links.",                                        "detection": "Monitor for clicks on suspicious URLs; track browser-initiated downloads; alert on safe links triggers."},
    "T1615":     {"name": "Group Policy Discovery",                             "tactic": "Discovery",            "description": "Adversaries gather information on Group Policy settings to identify escalation paths.",              "detection": "Monitor for gpresult and gpquery usage; alert on anomalous GPO enumeration from non-admin accounts."},
    "T1070":     {"name": "Indicator Removal",                                  "tactic": "Defense Evasion",      "description": "Adversaries delete or modify artifacts to remove evidence of their presence.",                        "detection": "Monitor for log clearing events (Event ID 1102/104); alert on shadow copy deletion."},
    "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs",        "tactic": "Defense Evasion",      "description": "Adversaries clear Windows Event Logs to hide intrusion activity.",                                   "detection": "Alert on Event ID 1102 (Security log cleared) and 104 (System log cleared); monitor wevtutil clear-log."},
}

# ============================================================
# Supporting lookup tables
# ============================================================
TACTIC_IDS = {
    "Initial Access": "TA0001", "Execution": "TA0002", "Persistence": "TA0003",
    "Privilege Escalation": "TA0004", "Defense Evasion": "TA0005",
    "Credential Access": "TA0006", "Discovery": "TA0007",
    "Lateral Movement": "TA0008", "Collection": "TA0009",
    "Command and Control": "TA0011", "Exfiltration": "TA0010",
    "Impact": "TA0040", "Not Mapped": "",
}

TACTIC_SLUG = {
    "Initial Access": "initialaccess", "Execution": "execution",
    "Persistence": "persistence", "Privilege Escalation": "privilegeescalation",
    "Defense Evasion": "defenseevasion", "Credential Access": "credentialaccess",
    "Discovery": "discovery", "Lateral Movement": "lateralmovement",
    "Collection": "collection", "Command and Control": "commandandcontrol",
    "Exfiltration": "exfiltration", "Impact": "impact", "Not Mapped": "unmapped",
}

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact", "Not Mapped",
]

D3FEND_BY_TACTIC = {
    "Initial Access":       {"primary": "Credential Hardening + Email Filtering + Platform Hardening", "techniques": ["Network Isolation (D3-NI): Restrict network exposure; limit inbound connectivity to essential paths.", "Platform Hardening (D3-PH): Apply patches, enforce secure configurations on internet-facing systems.", "Credential Hardening (D3-CH): Enforce MFA on all external authentication; use phishing-resistant credentials (FIDO2).", "Email Filtering (D3-EF): Deploy ATP email filtering to block malicious attachments and links before delivery."]},
    "Execution":            {"primary": "Application Hardening + Script Execution Analysis",           "techniques": ["Application Hardening (D3-AH): Implement application allowlisting to prevent unauthorized code execution.", "Execution Isolation (D3-EI): Use containerization, sandboxing, and process isolation.", "Script Execution Analysis (D3-SEA): Enable AMSI and Script Block Logging to block malicious scripts.", "Platform Monitoring (D3-PM): Monitor process creation events and command-line arguments."]},
    "Persistence":          {"primary": "Platform Monitoring + Account Management",                    "techniques": ["Platform Hardening (D3-PH): Restrict registry key modification permissions; disable startup locations.", "Boot Record Integrity (D3-BRI): Monitor and enforce integrity of boot records and startup configurations.", "Account Management (D3-AM): Enforce JIT/just-enough-access provisioning; review and audit accounts regularly.", "Platform Monitoring (D3-PM): Monitor for new scheduled tasks, services, and autostart registry key modifications."]},
    "Privilege Escalation": {"primary": "Privilege Restriction + Credential Hardening",                "techniques": ["Credential Hardening (D3-CH): Use Privileged Access Workstations (PAW); enforce just-enough-access model.", "Privilege Restriction (D3-PR): Implement least-privilege access; restrict local admin rights; tiered admin model.", "User Account Control (D3-UAC): Enforce UAC for administrative operations; monitor elevation events.", "Platform Monitoring (D3-PM): Alert on token manipulation APIs; monitor sensitive group membership changes."]},
    "Defense Evasion":      {"primary": "Platform Monitoring + Endpoint Health Beacon",                "techniques": ["Platform Monitoring (D3-PM): Deploy EDR with behavioral detection; enable process and file monitoring.", "Application Hardening (D3-AH): Block unsigned script execution; enforce WDAC/AppLocker policies.", "Endpoint Health Beacon (D3-EHB): Monitor security tool health status; alert on defensive tool tampering.", "Log Analysis (D3-LA): Centralize and protect log infrastructure; implement immutable logging."]},
    "Credential Access":    {"primary": "Multi-Factor Authentication + Credential Hardening",          "techniques": ["Credential Hardening (D3-CH): Enable Credential Guard; use gMSA for service accounts; enforce strong password policies.", "Multi-Factor Authentication (D3-MFA): Deploy phishing-resistant MFA (FIDO2) for all privileged accounts.", "Credential Vault Management (D3-CVM): Use PAM solutions; rotate credentials regularly.", "Platform Monitoring (D3-PM): Monitor LSASS access; alert on credential dumping patterns."]},
    "Discovery":            {"primary": "Network Isolation + Platform Monitoring",                     "techniques": ["Network Isolation (D3-NI): Segment networks to limit lateral visibility; implement zero-trust architecture.", "User Account Management (D3-UAM): Restrict enumeration rights; limit who can query directory services.", "Platform Monitoring (D3-PM): Alert on anomalous enumeration commands; monitor LDAP query volumes.", "Access Control (D3-AC): Implement RBAC; restrict access to directory enumeration APIs."]},
    "Lateral Movement":     {"primary": "Network Isolation + Credential Hardening",                    "techniques": ["Network Isolation (D3-NI): Implement micro-segmentation; restrict SMB/WMI/RDP between workstations.", "Credential Hardening (D3-CH): Eliminate credential reuse; deploy LAPS for local admin accounts.", "Protocol Isolation (D3-PI): Block unnecessary lateral movement protocols at host-based firewall level.", "Platform Monitoring (D3-PM): Monitor remote authentication events; alert on admin share access patterns."]},
    "Collection":           {"primary": "Data Loss Prevention + Access Control",                       "techniques": ["Data Loss Prevention (D3-DLP): Deploy DLP to detect and block sensitive data collection.", "File Encryption (D3-FE): Encrypt sensitive data at rest to limit value of collected information.", "Access Control (D3-AC): Restrict access to sensitive data repositories; implement need-to-know.", "Platform Monitoring (D3-PM): Monitor bulk file access and email forwarding rule creation."]},
    "Command and Control":  {"primary": "Network Traffic Analysis + DNS Allowlisting",                 "techniques": ["Network Traffic Analysis (D3-NTA): Deploy NDR/NTA to detect C2 beaconing and anomalous outbound connections.", "DNS Allowlisting (D3-DAL): Implement DNS sinkholes and allowlisting to block C2 domain resolution.", "Port Restriction (D3-PR): Block outbound connections to non-approved ports and protocols.", "Protocol Analysis (D3-PA): Inspect application layer protocols for C2 characteristics."]},
    "Exfiltration":         {"primary": "Data Loss Prevention + Network Traffic Analysis",             "techniques": ["Network Traffic Analysis (D3-NTA): Monitor for large or unusual outbound data transfers.", "Data Loss Prevention (D3-DLP): Implement DLP to detect and block sensitive data leaving the organization.", "Protocol Allowlisting (D3-PAL): Restrict outbound protocols; block unusual exfiltration channels.", "Endpoint Monitoring (D3-EM): Monitor for data staging and compression utilities."]},
    "Impact":               {"primary": "Backup + Service Hardening",                                  "techniques": ["Backup (D3-B): Maintain offline, immutable backups tested regularly for restoration.", "Data Recovery (D3-DR): Implement and test incident recovery procedures; use versioned storage.", "Service Hardening (D3-SH): Restrict which processes can stop critical services.", "Platform Monitoring (D3-PM): Alert on shadow copy deletion, mass file modification, and service termination."]},
    "Not Mapped":           {"primary": "Platform Monitoring + Access Control",                        "techniques": ["Platform Monitoring (D3-PM): Monitor for anomalous system and network activity.", "Access Control (D3-AC): Apply least-privilege principles to limit attack surface.", "Network Isolation (D3-NI): Segment networks and restrict lateral connectivity.", "Endpoint Health Beacon (D3-EHB): Ensure security tooling is healthy and active on all endpoints."]},
}

TACTIC_COLORS = {
    "Initial Access": "FF4C6EF5", "Execution": "FFFA8231", "Persistence": "FF20C997",
    "Privilege Escalation": "FFAE3EC9", "Defense Evasion": "FFFD7E14",
    "Credential Access": "FFFA5252", "Discovery": "FF4DABF7",
    "Lateral Movement": "FF339AF0", "Collection": "FF94D82D",
    "Command and Control": "FFE64980", "Exfiltration": "FFFF6B6B",
    "Impact": "FFE03131", "Not Mapped": "FF868E96",
}

# ============================================================
# Inference rules: (keyword_list, technique_id, weight)
# Higher weight = stronger signal. Title/folder adds 1x, desc 1x, query 2x
# ============================================================
INFERENCE_RULES = [
    # --- Impact ---
    (["ransomware", "double extention", "double extension", "file encrypt", "asrransomware", "asr ransomware"], "T1486", 4),
    (["shadow copy", "shadowcopy", "vssadmin", "inhibit recovery", "inhibitsystemrecovery"], "T1490", 4),
    (["service stop", "kill sql", "stop service", "killsql", "kill process"], "T1489", 4),
    (["data destruction", "cloud resource delet", "mass delet", "resource delet"], "T1485", 4),
    # --- Credential Access ---
    (["brute force", "password spray", "multiple failed", "account lock", "passwordspray"], "T1110", 4),
    (["credential dump", "lsass", "ntds.dit", "ntds dit", "mimikatz", "procdump"], "T1003", 4),
    (["kerberoast", "kerberos ticket", "silver ticket", "golden ticket", "kerb ticket"], "T1558.003", 4),
    (["adversary-in-the-middle", "adversary in the middle", "aitm", "storm-0539", "evilginx", "session hijack"], "T1557", 4),
    (["cleartext password", "unsecured credential", "plaintext password", "password in command", "password in argument"], "T1552", 4),
    # --- Lateral Movement ---
    (["lateral movement", "smb file copy", "admin share", "lateralmovement", "psexec", "pass-the-hash", "pass the hash", "wmiexec"], "T1021.002", 4),
    (["rdp", "remote desktop", "mstsc", "terminal service"], "T1021.001", 3),
    # --- Persistence ---
    (["web shell", "webshell"], "T1505.003", 4),
    (["scheduled task", "schtask", "task scheduler"], "T1053.005", 4),
    (["registry run", "autorun", "hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run", "startup folder"], "T1547.001", 4),
    (["office startup", "office macro", "xlstart", "word startup"], "T1137", 4),
    (["local account creat", "useraccount created", "accountcreated", "user account created"], "T1136.001", 4),
    (["domain account creat"], "T1136.002", 4),
    (["cloud account creat", "aad user creat", "new user created", "createuser"], "T1136.003", 4),
    (["conditional access", "modify authentication", "authentication process"], "T1556", 3),
    (["azure arc persist", "arc persist", "t1543", "create system process"], "T1543", 4),
    # --- Privilege Escalation ---
    (["runas saved", "savecred", "runaswith", "/savecred"], "T1134.002", 4),
    (["sudo", "sudoers", "sudoers group", "added to sudo"], "T1548.003", 4),
    (["sensitive group", "admin group add", "sensitive group add", "multisensitive"], "T1078.002", 4),
    (["graph permission", "all permission", "*.all permission", "graph api permission"], "T1098", 3),
    (["role addition", "role assignment", "ad role", "aad role", "pim activation", "pim role"], "T1098", 3),
    (["privilege escalat", "token manipulat", "access token"], "T1134", 3),
    (["gpo", "group policy modif"], "T1484.001", 4),
    # --- Defense Evasion ---
    (["powershell encoded", "encodedcommand", "base64 encoded", "encoded command", "-enc ", "-e base64"], "T1027", 4),
    (["command obfuscat", "invoke-obfuscat", "amsi bypass"], "T1027.010", 4),
    (["log clear", "event log clear", "wevtutil", "security log clear", "clearlog", "clear-log", "audit log delet"], "T1070.001", 4),
    (["regsvr32"], "T1218.010", 4),
    (["msbuild"], "T1127.001", 4),
    (["mark-of-the-web", "mark of the web", "iso file", "motw", "rare iso", "vhd file", ".iso"], "T1553.005", 4),
    (["disable defender", "disable antivirus", "disable-defender", "set-mppreference", "disabledefender", "tamper protection"], "T1562.001", 4),
    (["offboarding", "offboard package", "mde offboard"], "T1562.001", 3),
    (["kerberos downgrade", "encryption downgrade", "rc4 encryption", "rc4 kerberos"], "T1562.010", 4),
    (["custom detection delet", "indicator delet"], "T1070", 3),
    (["process inject", "dll inject", "reflective"], "T1055", 4),
    # --- Execution ---
    (["wmic", "wmiprvse", "win32_process", "wmi command", "wmi execution", "wmic process"], "T1047", 4),
    (["powershell", "pwsh", "powershell_ise"], "T1059.001", 2),
    (["cmd.exe", "command shell", "cmd /c"], "T1059.003", 2),
    # --- Discovery ---
    (["network sniff", "promiscuous", "pcap", "packet capture", "netsh trace"], "T1040", 4),
    (["port scan", "network scan", "service scan", "database discover", "database service", "nmap"], "T1046", 4),
    (["net.exe discovery", "net1.exe", "net command", "discovery activit", "netdiscovery"], "T1087", 3),
    (["ldap", "anomalous ldap", "ldap traffic", "ldap query"], "T1087.002", 3),
    (["azurehound", "bloodhound", "sharphound"], "T1069.003", 4),
    (["group policy discover", "gpo discover", "gpresult", "gpquery"], "T1615", 4),
    (["wmic antivirus", "defender discover", "security software discover", "security product", "av discover"], "T1518.001", 4),
    (["smb session", "remote system discover", "host discover", "anomalous smb"], "T1018", 3),
    (["download all user", "bulk user", "user enumerat", "account enumerat"], "T1087.004", 3),
    (["local group discover", "localgroup"], "T1069.001", 3),
    (["cloud discovery", "cloud group discover", "azure ad download", "azure ad group"], "T1069.003", 3),
    (["password policy", "password never expire", "password expir", "passwdlastset"], "T1201", 3),
    (["security software", "defender activit", "defender component", "defender discov"], "T1518.001", 3),
    (["whoami", "systeminfo", "ipconfig", "hostname discover"], "T1082", 3),
    # --- Initial Access ---
    (["phishing", "spearphishing", "phish campaign"], "T1566", 4),
    (["email attach", "executable email", "macro attach", "malicious attach"], "T1566.001", 4),
    (["safe link", "safe links trigger", "url click"], "T1566.002", 4),
    (["exploit", "vulnerability", "cve-", "public-facing", "internet facing", "known exploited", "cisa kev"], "T1190", 3),
    (["cloud account", "cloud persist", "cloud sign", "new auth app", "new authentication app"], "T1078.004", 3),
    (["guest user", "external user", "b2b user"], "T1078.004", 2),
    (["break glass", "breakglass", "emergency account"], "T1078.004", 3),
    (["sign in from new country", "new country sign", "successful sign in from new"], "T1078", 3),
    (["new user agent", "new agent", "useragent", "sign in by browser", "sign in by os"], "T1078", 2),
    # --- Command and Control ---
    (["anydesk", "teamviewer", "netsupport", "remote access tool", "rat ", "rmm tool", "remote management"], "T1219", 4),
    (["certutil", "bitsadmin", "tool transfer", "download cradle", "invoke-webrequest", "wget", "curl download"], "T1105", 3),
    (["proxy", "anonymous proxy", "vpn detection", "cloud app proxy"], "T1090", 3),
    (["telegram", "c2 beacon", "c2 traffic", "command and control"], "T1071.001", 3),
    # --- Exfiltration ---
    (["exfil", "data transfer out", "data leak", "upload to"], "T1048", 4),
    # --- Collection ---
    (["email collect", "mailbox", "mail forward", "inbox rule"], "T1114", 3),
    # --- USB / Removable Media ---
    (["usb", "removable media", "removable device", "usb device", "usbstor"], "T1091", 4),
    # --- Threat Intelligence (often initial access or C2) ---
    (["ti feed", "threat intel", "ioc", "indicator of compromise", "malware hash", "malicious ip", "c2 ip"], "T1071", 2),
    # --- Vulnerability Management ---
    (["vulnerability", "cve", "patch", "cvss", "exposed", "missing patch"], "T1190", 2),
    # --- DFIR signals ---
    (["dfir", "incident response", "compromise", "compromised account"], "T1078", 2),
]

# ============================================================
# File/folder → technique quick-map for well-known patterns
# ============================================================
FILENAME_TECHNIQUE_MAP = {
    # file stem (lower, no spaces) → (tech_id, confidence)
    "localaccountcreated":                   ("T1136.001", 5),
    "localadminadditions":                   ("T1136.001", 5),
    "commandlineuseraddition":               ("T1136.002", 5),
    "cloudpersistenceactivitybyuseratrisk":  ("T1136.003", 5),
    "shadowcopydeletion":                    ("T1490", 5),
    "wevtutilclearlogs":                     ("T1070.001", 5),
    "securitylogcleared":                    ("T1070.001", 5),
    "ntdsditfilemodifications":              ("T1003.003", 5),
    "runaswiths savedcredentials":           ("T1134.002", 5),
    "runaswithsavedcredentials":             ("T1134.002", 5),
    "multiplesentitivegroupadditions":       ("T1078.002", 5),
    "commandlinewithcleartextpassword":      ("T1552", 5),
    "windowsnetworksniffing":                ("T1040", 5),
    "anomalousldaptraffic":                  ("T1087.002", 5),
    "anomalousgroupolicydiscovery":          ("T1615", 5),
    "usbdeviceconnected":                    ("T1091", 5),
    "usbstoragestats":                       ("T1091", 5),
    "adrroleadditions":                      ("T1098", 4),
    "adroladditions":                        ("T1098", 4),
    "guestuserswithadroles":                 ("T1098", 4),
    "monitorcloudbreakglassaccount":         ("T1078.004", 4),
    "newuseragentused":                      ("T1078", 3),
    "signinsbybrowser":                      ("T1078", 3),
    "signinsbyos":                           ("T1078", 3),
    "signinsbyuseragent":                    ("T1078", 3),
    "successfulsigninfromnewcountry":        ("T1078", 4),
    "top10userswiththemostsigninipsused":    ("T1078", 3),
    "topnaccountslongestperiodwithoutpasswordreset": ("T1110", 3),
    "totallallgraphpermissionsadded":        ("T1098", 4),
    "totalallgraphpermissionsadded":         ("T1098", 4),
    "securityalerttriggeredbyriskyuser":     ("T1078", 3),
    "smartscreenurl":                        ("T1566.002", 4),
    "smartscreennetworkprotection":          ("T1566.002", 4),
}

FOLDER_TECHNIQUE_BIAS = {
    # Folder name lower → (tech_id, bonus_weight) applied to all files in that folder
    "ransomware":          ("T1486", 3),
    "asr rules":           ("T1486", 2),
    "living off the land": ("T1218", 2),
    "usb":                 ("T1091", 4),
    "smartscreen":         ("T1566.002", 3),
    "linux":               ("T1059", 1),
    "vulnerability management": ("T1190", 2),
}


# ============================================================
# Helpers
# ============================================================

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
    m = re.search(r"####\s+Description\s*\n(.*?)(?=\n####|\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
    if m:
        d = re.sub(r"\s+", " ", m.group(1)).strip()
        return (d[:600] + "…") if len(d) > 600 else d
    return ""


def extract_risk(content):
    m = re.search(r"####\s+Risk\s*\n(.*?)(?=\n####|\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
    if m:
        r = re.sub(r"\s+", " ", m.group(1)).strip()
        return (r[:400] + "…") if len(r) > 400 else r
    return ""


def extract_platforms(content):
    found = []
    for name in ["Defender For Endpoint", "Sentinel", "Defender For Identity",
                 "Defender For Cloud Apps", "Graph API", "Azure Active Directory",
                 "Defender XDR", "Log Analytics", "Azure Resource Graph"]:
        if re.search(r"##\s+" + re.escape(name), content, re.IGNORECASE):
            found.append(name)
    return found if found else ["Unknown"]


def extract_query(content):
    """
    Extract the primary KQL query from the file.
    Prefers Defender For Endpoint; falls back to Sentinel.
    Returns (query_text, platform) tuple. Truncates to 3000 chars.
    """
    # Find platform sections and their code blocks
    platform_order = [
        "Defender For Endpoint", "Sentinel", "Defender For Identity",
        "Defender For Cloud Apps", "Defender XDR", "Azure Active Directory",
        "Graph API", "Log Analytics", "Azure Resource Graph",
    ]
    for platform in platform_order:
        # Match ## Platform heading then grab first ``` block
        pat = re.escape(f"## {platform}")
        m = re.search(pat + r".*?```(?:KQL|kql|sql)?\s*\n(.*?)```", content, re.DOTALL | re.IGNORECASE)
        if m:
            q = m.group(1).strip()
            if len(q) > 3000:
                q = q[:3000] + "\n// [truncated]"
            return q, platform
    # Last resort: any code block
    m = re.search(r"```(?:KQL|kql)?\s*\n(.*?)```", content, re.DOTALL | re.IGNORECASE)
    if m:
        q = m.group(1).strip()
        if len(q) > 3000:
            q = q[:3000] + "\n// [truncated]"
        return q, "Unknown"
    return "", ""


def extract_mitre_table(content):
    """Parse MITRE ATT&CK table from markdown file. Returns list of (tid, tname)."""
    results = []
    m = re.search(
        r"####\s+MITRE ATT&CK Technique\(s\)(.*?)(?=\n####|\n##|\Z)",
        content, re.DOTALL | re.IGNORECASE,
    )
    if not m:
        return results
    for row in re.finditer(r"\|\s*(T\d{4}(?:\.\d{3})?)\s*\|\s*([^|]+?)\s*\|", m.group(1)):
        tid = row.group(1).upper().strip()
        tname = row.group(2).strip()
        if tid not in [r[0] for r in results]:
            results.append((tid, tname))
    return results


def infer_mitre(file_path, title, content, description, risk, repo_root):
    """
    Multi-signal MITRE technique inference.
    Returns list of (technique_id, score) sorted by score desc.
    """
    rel = Path(file_path).relative_to(repo_root) if repo_root else Path(file_path)
    path_parts = [p.lower() for p in rel.parts]
    stem_clean = re.sub(r"[^a-z0-9]", "", rel.stem.lower())
    query, _ = extract_query(content)

    # Combined text signals (lowercased)
    name_text    = f"{title} {rel.stem}".lower()
    desc_text    = f"{description} {risk}".lower()
    query_text   = query.lower()
    folder_text  = " ".join(path_parts[:-1])  # folder names only

    scores = defaultdict(int)

    # 0. Exact file stem lookup (highest priority)
    if stem_clean in FILENAME_TECHNIQUE_MAP:
        tid, conf = FILENAME_TECHNIQUE_MAP[stem_clean]
        scores[tid] += conf

    # 1. Folder bias
    for folder_kw, (tid, weight) in FOLDER_TECHNIQUE_BIAS.items():
        if folder_kw in folder_text:
            scores[tid] += weight

    # 2. Inference rules
    for keywords, tid, weight in INFERENCE_RULES:
        for kw in keywords:
            if kw in name_text:
                scores[tid] += weight
            if kw in desc_text:
                scores[tid] += weight
            if kw in query_text:
                scores[tid] += weight * 2  # query content is strongest signal

    # Return sorted list, only include if score >= threshold
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    return [(tid, s) for tid, s in ranked if s >= 3]


# ============================================================
# Collect all records
# ============================================================

SKIP_FILES = {"README.md", "DetectionTemplate.md", "Mapping.md", "TheArtOfKnowingYourData.md"}
SKIP_DIRS  = {"MITRE ATT&CK", "Functions", "KQL Regex", "Learning", "MISP", "Fun"}


def collect_all_records(repo_root):
    repo_root = Path(repo_root)
    records = []

    for md_path in sorted(repo_root.rglob("*.md")):
        if md_path.name in SKIP_FILES:
            continue
        if any(part in SKIP_DIRS for part in md_path.relative_to(repo_root).parts):
            continue

        content = read_file_safe(md_path)
        if not content:
            continue

        title       = extract_title(content) or md_path.stem
        description = extract_description(content)
        risk        = extract_risk(content)
        platforms   = extract_platforms(content)
        query, _    = extract_query(content)
        rel_display = str(md_path.relative_to(repo_root))
        category    = md_path.relative_to(repo_root).parts[0]

        explicit_entries = extract_mitre_table(content)

        if explicit_entries:
            mapping_type = "Explicit"
            for tech_id, tech_name_from_file in explicit_entries:
                tech_info = ATTACK_TECHNIQUES.get(tech_id) or ATTACK_TECHNIQUES.get(tech_id.split(".")[0], {})
                tactic    = tech_info.get("tactic", "Not Mapped")
                records.append(_make_record(
                    title, category, tactic, tech_id,
                    tech_info.get("name", tech_name_from_file),
                    tech_info.get("description", ""),
                    tech_info.get("detection", ""),
                    mapping_type, platforms, description, risk, query, rel_display,
                ))
        else:
            # Infer
            inferred = infer_mitre(md_path, title, content, description, risk, repo_root)
            if inferred:
                mapping_type = "Inferred"
                # Take top-3 inferred techniques
                for tech_id, score in inferred[:3]:
                    tech_info = ATTACK_TECHNIQUES.get(tech_id) or ATTACK_TECHNIQUES.get(tech_id.split(".")[0], {})
                    tactic    = tech_info.get("tactic", "Not Mapped")
                    records.append(_make_record(
                        title, category, tactic, tech_id,
                        tech_info.get("name", ""),
                        tech_info.get("description", ""),
                        tech_info.get("detection", ""),
                        f"Inferred (score={score})", platforms, description, risk, query, rel_display,
                    ))
            else:
                # Truly unmapped
                records.append(_make_record(
                    title, category, "Not Mapped", "", "", "", "",
                    "Not Mapped", platforms, description, risk, query, rel_display,
                ))

    return records


def _make_record(title, category, tactic, tech_id, tech_name, tech_desc, detection,
                 mapping_type, platforms, description, risk, query, rel_display):
    d3   = D3FEND_BY_TACTIC.get(tactic, D3FEND_BY_TACTIC["Not Mapped"])
    slug = TACTIC_SLUG.get(tactic, "unmapped")
    canonical = f"{slug}-{slugify(title)}"
    tech_url  = (f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}" if tech_id else "")
    return {
        "Canonical Name":               canonical,
        "Query Title":                  title,
        "Category":                     category,
        "MITRE Tactic":                 tactic,
        "Tactic ID":                    TACTIC_IDS.get(tactic, ""),
        "Technique ID":                 tech_id,
        "Technique Name":               tech_name,
        "Technique Description":        tech_desc,
        "ATT&CK Technique URL":         tech_url,
        "Detection Strategy (ATT&CK)":  detection,
        "D3FEND Primary Strategy":      d3.get("primary", ""),
        "D3FEND Defensive Techniques":  "\n".join(d3.get("techniques", [])),
        "D3FEND URL":                   "https://d3fend.mitre.org/",
        "Mapping Type":                 mapping_type,
        "Platforms":                    ", ".join(platforms),
        "Query Description":            description,
        "Risk":                         risk,
        "Query (KQL)":                  query,
        "File Path":                    rel_display,
    }


# ============================================================
# Excel generation
# ============================================================

COLUMNS = [
    "Canonical Name", "Query Title", "Category",
    "MITRE Tactic", "Tactic ID", "Technique ID", "Technique Name",
    "Technique Description", "ATT&CK Technique URL",
    "Detection Strategy (ATT&CK)",
    "D3FEND Primary Strategy", "D3FEND Defensive Techniques", "D3FEND URL",
    "Mapping Type", "Platforms",
    "Query Description", "Risk",
    "Query (KQL)",
    "File Path",
]

COLUMN_WIDTHS = {
    "Canonical Name": 45, "Query Title": 42, "Category": 25,
    "MITRE Tactic": 22, "Tactic ID": 12, "Technique ID": 14, "Technique Name": 44,
    "Technique Description": 68, "ATT&CK Technique URL": 55,
    "Detection Strategy (ATT&CK)": 68,
    "D3FEND Primary Strategy": 45, "D3FEND Defensive Techniques": 78, "D3FEND URL": 32,
    "Mapping Type": 18, "Platforms": 38,
    "Query Description": 68, "Risk": 52,
    "Query (KQL)": 80,
    "File Path": 58,
}


def thin_border():
    s = Side(style="thin", color="FFD0D0D0")
    return Border(left=s, right=s, top=s, bottom=s)


def write_header_row(ws, row_num, columns, fill_hex):
    fill  = PatternFill("solid", fgColor=fill_hex)
    font  = Font(name="Calibri", bold=True, color="FFFFFFFF", size=11)
    align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    for ci, col in enumerate(columns, start=1):
        c = ws.cell(row=row_num, column=ci, value=col)
        c.fill, c.font, c.alignment, c.border = fill, font, align, thin_border()
    ws.row_dimensions[row_num].height = 30


def write_data_rows(ws, records, columns, start_row=2):
    wrap     = Alignment(vertical="top", wrap_text=True)
    alt_fill = PatternFill("solid", fgColor="FFF8F9FA")
    for ri, rec in enumerate(records, start=start_row):
        tactic    = rec.get("MITRE Tactic", "Not Mapped")
        tac_color = TACTIC_COLORS.get(tactic, "FF868E96")
        for ci, col in enumerate(columns, start=1):
            val = rec.get(col, "")
            c   = ws.cell(row=ri, column=ci, value=val)
            c.alignment, c.border = wrap, thin_border()
            if col == "MITRE Tactic":
                c.fill = PatternFill("solid", fgColor=tac_color)
                c.font = Font(color="FFFFFFFF", bold=True)
            elif col == "Mapping Type":
                if "Inferred" in str(val):
                    c.fill = PatternFill("solid", fgColor="FFFFF3CD")
                elif val == "Explicit":
                    c.fill = PatternFill("solid", fgColor="FFD4EDDA")
            elif ri % 2 == 0:
                c.fill = alt_fill


def set_col_widths(ws, columns):
    for ci, col in enumerate(columns, start=1):
        ws.column_dimensions[get_column_letter(ci)].width = COLUMN_WIDTHS.get(col, 30)


def write_excel(records, output_path):
    wb = openpyxl.Workbook()

    # ── Summary ──────────────────────────────────────────────
    ws_sum = wb.active
    ws_sum.title = "Summary"
    tf = Font(name="Calibri", size=16, bold=True, color="FF2F4F8F")
    ws_sum["A1"] = "MITRE ATT&CK Detection & D3FEND Mapping"
    ws_sum["A1"].font = tf
    ws_sum["A2"] = "Repository: Hunting-Queries-Detection-Rules (github.com/Bert-JanP)"
    unique_files = len(set(r["File Path"] for r in records))
    explicit  = sum(1 for r in records if r["Mapping Type"] == "Explicit")
    inferred  = sum(1 for r in records if "Inferred" in str(r["Mapping Type"]))
    unmapped  = sum(1 for r in records if r["Mapping Type"] == "Not Mapped")
    ws_sum["A3"] = f"Total Query Files Scanned: {unique_files}"
    ws_sum["A4"] = f"Total Rows (file × technique): {len(records)}"
    ws_sum["A5"] = f"Explicit MITRE Mapping: {explicit} rows"
    ws_sum["A6"] = f"Inferred MITRE Mapping: {inferred} rows"
    ws_sum["A7"] = f"Not Mapped: {unmapped} rows"
    ws_sum["A9"]  = "Tactic";          ws_sum["A9"].fill  = PatternFill("solid", fgColor="FF2F4F8F");  ws_sum["A9"].font  = Font(bold=True, color="FFFFFFFF")
    ws_sum["B9"]  = "Total Rows";      ws_sum["B9"].fill  = PatternFill("solid", fgColor="FF2F4F8F");  ws_sum["B9"].font  = Font(bold=True, color="FFFFFFFF")
    ws_sum["C9"]  = "Unique Files";    ws_sum["C9"].fill  = PatternFill("solid", fgColor="FF2F4F8F");  ws_sum["C9"].font  = Font(bold=True, color="FFFFFFFF")
    tactic_rows  = Counter(r["MITRE Tactic"] for r in records)
    tactic_files = defaultdict(set)
    for r in records:
        tactic_files[r["MITRE Tactic"]].add(r["File Path"])
    for i, tactic in enumerate(TACTIC_ORDER, start=10):
        if tactic not in tactic_rows: continue
        col = TACTIC_COLORS.get(tactic, "FF868E96")
        ws_sum.cell(row=i, column=1, value=tactic).fill = PatternFill("solid", fgColor=col)
        ws_sum.cell(row=i, column=1).font = Font(color="FFFFFFFF", bold=True)
        ws_sum.cell(row=i, column=2, value=tactic_rows[tactic])
        ws_sum.cell(row=i, column=3, value=len(tactic_files[tactic]))
    for col, w in [("A", 28), ("B", 12), ("C", 16)]:
        ws_sum.column_dimensions[col].width = w

    # ── All Queries ───────────────────────────────────────────
    ws_all = wb.create_sheet("All Queries")
    write_header_row(ws_all, 1, COLUMNS, "FF2F4F8F")
    write_data_rows(ws_all, records, COLUMNS)
    ws_all.freeze_panes = "A2"
    ws_all.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}1"
    set_col_widths(ws_all, COLUMNS)

    # ── MITRE Mapped ─────────────────────────────────────────
    mapped = [r for r in records if r["MITRE Tactic"] != "Not Mapped"]
    ws_map = wb.create_sheet("MITRE Mapped")
    write_header_row(ws_map, 1, COLUMNS, "FF2F4F8F")
    write_data_rows(ws_map, mapped, COLUMNS)
    ws_map.freeze_panes = "A2"
    ws_map.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}1"
    set_col_widths(ws_map, COLUMNS)

    # ── Per-tactic sheets ─────────────────────────────────────
    by_tactic = defaultdict(list)
    for r in records:
        by_tactic[r["MITRE Tactic"]].append(r)

    for tactic in TACTIC_ORDER:
        t_recs = by_tactic.get(tactic, [])
        if not t_recs: continue
        col = TACTIC_COLORS.get(tactic, "FF868E96")
        ws_t = wb.create_sheet(tactic[:31])
        # Banner
        ws_t.merge_cells(f"A1:{get_column_letter(len(COLUMNS))}1")
        b = ws_t["A1"]
        b.value = f"ATT&CK: {tactic}  |  {TACTIC_IDS.get(tactic, 'N/A')}  |  Queries: {len(t_recs)}"
        b.font, b.fill = Font(name="Calibri", size=13, bold=True, color="FFFFFFFF"), PatternFill("solid", fgColor=col)
        b.alignment = Alignment(horizontal="center", vertical="center")
        ws_t.row_dimensions[1].height = 26
        # D3FEND row
        d3 = D3FEND_BY_TACTIC.get(tactic, D3FEND_BY_TACTIC["Not Mapped"])
        ws_t.merge_cells(f"A2:{get_column_letter(len(COLUMNS))}2")
        d = ws_t["A2"]
        d.value = f"D3FEND Primary Defense: {d3.get('primary', '')}"
        d.font, d.alignment = Font(bold=True, color="FF2F4F8F", size=10), Alignment(horizontal="left", vertical="center")
        ws_t.row_dimensions[2].height = 18
        # Header + data
        write_header_row(ws_t, 3, COLUMNS, col)
        write_data_rows(ws_t, t_recs, COLUMNS, start_row=4)
        ws_t.freeze_panes = "A4"
        ws_t.auto_filter.ref = f"A3:{get_column_letter(len(COLUMNS))}3"
        set_col_widths(ws_t, COLUMNS)

    wb.save(output_path)
    print(f"\n✓  Saved: {output_path}")
    print(f"   Total rows   : {len(records)}")
    print(f"   Explicit     : {explicit}")
    print(f"   Inferred     : {inferred}")
    print(f"   Not Mapped   : {unmapped}")
    print(f"   Sheets       : {len(wb.sheetnames)}")


# ============================================================
# Main
# ============================================================

def main():
    repo_root = Path(__file__).parent.parent.resolve()
    print(f"Repository: {repo_root}")
    print("Scanning all .md files …")

    records = collect_all_records(repo_root)

    tactic_order_map = {t: i for i, t in enumerate(TACTIC_ORDER)}
    records.sort(key=lambda r: (
        tactic_order_map.get(r["MITRE Tactic"], 99),
        r.get("Technique ID", ""),
        r["Query Title"].lower(),
    ))

    out = repo_root / "MITRE ATT&CK" / "MITRE_ATT&CK_Detection_D3FEND_Mapping.xlsx"
    write_excel(records, out)


if __name__ == "__main__":
    main()
