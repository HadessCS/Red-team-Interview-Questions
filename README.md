
# Red Team Interview Questions

Welcome to the Red Team Interview Questions repository! This repository aims to provide a comprehensive list of topics and questions that can be helpful for both interviewers and candidates preparing for red team-related roles. Whether you're looking to assess your knowledge or preparing to interview candidates, these questions cover a wide range of essential topics in the field of red teaming.

## Table of Contents

1. [Initial Access](#initial-access)
2. [Windows Network](#windows-network)
3. [Active Directory](#active-directory)
4. [OS Language Programming](#os-language-programming)
5. [PowerShell](#powershell)
6. [Windows Internals](#windows-internals)
7. [DNS Server](#dns-server)
8. [Windows API](#windows-api)
9. [Macro Attack](#macro-attack)
10. [APT Groups](#apt-groups)
11. [EDR and Antivirus](#edr-and-antivirus)
12. [Malware Development](#malware-development)
13. [System & Kernel Programming](#system--kernel-programming)
14. [Privilege Escalation](#privilege-escalation)
15. [Post-exploitation (and Lateral Movement)](#post-exploitation-and-lateral-movement)
16. [Persistence](#persistence)
17. [Breaking Hash](#breaking-hash)
18. [C&C (Command and Control)](#cc-command-and-control)
19. [DLL](#dll)
20. [DNS Rebinding](#dns-rebinding)
21. [LDAP](#ldap)
22. [Evasion](#evasion)
23. [Steganography](#steganography)
24. [Kerberoasting and Kerberos](#kerberoasting-and-kerberos)
25. [Mimikatz](#mimikatz)
26. [RDP](#rdp)
27. [NTLM](#ntlm)
28. [YARA Language](#yara-language)
29. [Windows API And DLL Difference](#windows-api-and-dll-difference)
30. [Antivirus and EDR Difference](#antivirus-and-edr-difference)
31. [NTDLL](#ntdll)
32. [Native API](#native-api)
33. [Windows Driver](#windows-driver)
34. [Tunneling](#tunneling)
35. [Shadow File](#shadow-file)
36. [SAM File](#sam-file)
37. [LSA](#lsa)
38. [LSASS](#lsass)
39. [WDIGEST](#wdigest)
40. [CredSSP](#credssp)
41. [MSV](#msv)
42. [LiveSSP](#livessp)
43. [TSpkg](#tspkg)
44. [CredMan](#credman)
45. [EDR NDR XDR](#edr-ndr-xdr)
46. [Polymorphic Malware](#polymorphic-malware)
47. [Pass-the-Hash, Pass-the-Ticket or Build Golden Tickets](#pass-the-hash-pass-the-ticket-or-build-golden-tickets)
48. [Firewall](#firewall)
49. [WinDBG (Windows Debugger)](#windbg-windows-debugger)
50. [PE (Portable Executable)](#pe-portable-executable)
51. [ICMP](#icmp)
52. [Major Microsoft frameworks for Windows](#major-microsoft-frameworks-for-windows)
53. [Services and Processes](#services-and-processes)
54. [svchost](#svchost)
55. [CIM Class](#cim-class)
56. [CDB, NTSD, KD, Gflags, GflagsX, PE Explorer](#cdb-ntsd-kd-gflags-gflagsx-pe-explorer)
57. [Sysinternals Suite (tools)](#sysinternals-suite-tools)
58. [Undocumented Functions](#undocumented-functions)
59. [Process Explorer vs Process Hacker](#process-explorer-vs-process-hacker)
60. [CLR (Common Language Runtime)](#clr-common-language-runtime)

## Initial Access:
### Question 1:
**How do you typically gain initial access to a target network?**
- *Answer:* Initial access to a target network is typically gained through techniques such as phishing, exploiting vulnerabilities, or leveraging misconfiguration.

### Question 2:
**What are some common methods used for gaining initial access to a target network?**
- *Answer:* Common methods include:
  - Phishing attacks
  - Exploiting software vulnerabilities (e.g., remote code execution)
  - Brute-force attacks on authentication mechanisms
  - Social engineering tactics

### Question 3:
**Can you explain the difference between phishing and spear phishing?**
- *Answer:* 
  - **Phishing:** A generic term for deceptive email messages aimed at tricking recipients into divulging sensitive information or installing malware.
  - **Spear Phishing:** A targeted form of phishing that tailors the attack to a specific individual or organization, often using personalized information to increase the chances of success.

### Question 4:
**How can an attacker exploit vulnerable services to gain initial access?**
- *Answer:* Attackers can exploit vulnerable services by targeting known vulnerabilities in software running on networked devices. This includes unpatched operating systems, outdated software versions, or misconfigured services exposed to the internet.

### Question 5:
**Describe a scenario where an attacker leverages social engineering for initial access.**
- *Answer:* In a social engineering scenario, an attacker might impersonate a trusted individual or organization to trick a victim into revealing login credentials, downloading malware disguised as legitimate software, or providing access to sensitive information.

---

## Windows Network:
### Question 1:
**Explain the role of DHCP, DNS, TCP/IP, and OSI in Windows networking.**
- **Answer:** DHCP is responsible for IP address allocation, DNS for name resolution, TCP/IP for communication, and OSI serves as a conceptual model.

### Question 2:
**Explain the role of DHCP in network configuration.**
- **Answer:** DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses and other network configuration parameters to devices on a network, simplifying network setup and management.

### Question 3:
**How does DNS resolve domain names to IP addresses?**
- **Answer:** DNS (Domain Name System) translates human-readable domain names (e.g., example.com) into IP addresses that computers use to communicate over a network.

### Question 4:
**Describe the TCP/IP model and its layers.**
- **Answer:** The TCP/IP model consists of four layers: Application, Transport, Internet, and Network Interface. Each layer handles specific aspects of network communication, such as data formatting, routing, and error detection.

### Question 5:
**How does VPN enhance network security and privacy?**
- **Answer:** VPN (Virtual Private Network) encrypts network traffic between a user's device and a VPN server, providing confidentiality and integrity for data transmitted over insecure networks like the internet.

---

## Active Directory
### Question 1:
**What is Active Directory, and what role does it play in a Windows network?**
- *Answer:* Active Directory is a directory service developed by Microsoft for managing network resources, including users, computers, and groups, in a Windows domain environment.

### Question 2:
**How are users and resources organized within an Active Directory structure?**
- *Answer:* Users and resources are organized into a hierarchical structure called a domain, which can contain organizational units (OUs) for further organization and delegation of administrative tasks.

### Question 3:
**Explain the process of authentication and authorization in Active Directory.**
- *Answer:* Authentication verifies the identity of users and computers accessing resources in the Active Directory domain, while authorization determines the permissions granted to authenticated users or groups.

### Question 4:
**What are some common Active Directory attack techniques, and how can they be mitigated?**
- *Answer:* Common attack techniques include pass-the-hash, golden ticket attacks, and Kerberoasting. Mitigation strategies include enforcing strong password policies, monitoring privileged account usage, and implementing least privilege access controls.

### Question 5:
**Why is Active Directory a prime target for attackers?**
- *Answer:* Active Directory centralizes authentication and authorization services, making it a valuable target for gaining control over a network.

---

## OS Language Programming
### Question 1:
**What are the main differences between C and C++?**
- *Answer:* C is a procedural programming language, while C++ is an object-oriented programming language that also supports procedural programming.

### Question 2:
**Explain the concept of pointers in C/C++?**
- *Answer:* Pointers are variables that store memory addresses, allowing direct manipulation of memory locations and efficient memory management.

### Question 3:
**How do you manage memory allocation in C/C++?**
- *Answer:* In C, memory allocation is managed using functions like malloc and free, while in C++, memory management is often handled by constructors and destructors of objects.

### Question 4:
**Can you provide an example of a basic C/C++ program?**
- *Answer:* simple "Hello, World!" program in C++ (it can be more complicated and this question is just for example):
```cpp
#include <iostream>
using namespace std;

int main() {
    cout << "Hello, World!" << endl;
    return 0;
}
```

### Question 5:
**What are the basic concepts of C and C++ programming languages?**
- *Answer:*  C is a procedural language, while C++ is an object-oriented language, both commonly used for system programming.

---


## PowerShell
### Question 1:
**Question: How can PowerShell be used for scripting and automation in a Red Team scenario?**
- *Answer:* PowerShell provides powerful scripting capabilities for tasks such as reconnaissance, lateral movement, and payload execution.

### Question 2:
**Question: What is PowerShell, and how does it differ from traditional command-line interfaces?**
- *Answer:* PowerShell is a task automation and configuration management framework from Microsoft. Unlike traditional command-line interfaces, PowerShell is based on a scripting language and provides access to a wide range of system administration tasks via cmdlets.

### Question 3:
**Question: Describe how PowerShell can be used for scripting and automation tasks.**
- *Answer:* PowerShell scripts can automate tasks such as system configuration, file management, network administration, and software deployment by executing sequences of cmdlets and script blocks.

### Question 4:
**Question: What are cmdlets, and how are they used in PowerShell?**
- *Answer:* Cmdlets (command-lets) are lightweight commands used in PowerShell for performing specific actions, such as retrieving system information, managing files, or interacting with services.

### Question 5:
**Question: Can you demonstrate a simple PowerShell script for automating a common task?**
- *Answer:* PowerShell script that lists all files in a directory:
```powershell
Get-ChildItem -Path C:\MyFolder
```

---

## Windows Internals
### Question 1:
**Why is understanding Windows internals crucial for Red Team operations?**
- *Answer:* It allows for the identification of vulnerabilities, weaknesses, and potential attack vectors within the Windows operating system.

### Question 2:
**What are Windows Internals, and why are they important for cybersecurity professionals?**
- *Answer:* Windows Internals refers to the inner workings of the Windows operating system, including its architecture, kernel components, system services, and data structures. Understanding Windows Internals is crucial for cybersecurity professionals to analyze and defend against advanced threats targeting the Windows platform.

### Question 3:
**Describe the difference between user mode and kernel mode in Windows.**
- *Answer:* User mode is a restricted execution environment where applications run with limited access to system resources, while kernel mode is a privileged execution environment where the operating system's core components execute with full access to hardware and system resources.

### Question 4:
**What tools are commonly used for Windows Internals analysis and troubleshooting?**
- *Answer:* Tools like Process Explorer, Process Monitor, WinDbg, and Sysinternals Suite are commonly used for Windows Internals analysis and troubleshooting tasks.

### Question 5:
**Explain the significance of the Windows Registry in Windows Internals.**
- *Answer:* The Windows Registry is a centralized database that stores configuration settings and options for the Windows operating system and installed applications. It plays a crucial role in system configuration, software installation, and system performance.

---

## DNS Server
### Question 1:
**What are common DNS server misconfigurations that can be exploited by attackers?**
- *Answer:* Misconfigured DNS servers can be used for DNS spoofing, cache poisoning, or amplification attacks.

### Question 2:
**What is DNS (Domain Name System), and why is it important for network communication?**
- *Answer:* DNS is a hierarchical decentralized naming system that translates human-readable domain names (e.g., example.com) into IP addresses (e.g., 192.0.2.1), allowing computers to locate resources on a network using domain names.

### Question 3:
**Describe the process of DNS resolution.**
- *Answer:* DNS resolution involves querying DNS servers to translate domain names into IP addresses. The process typically includes recursive and iterative queries until a matching IP address is found or an error occurs.

### Question 4:
**What are the main types of DNS records, and what purposes do they serve?**
- *Answer:* Common DNS records include A records (IPv4 address mapping), AAAA records (IPv6 address mapping), CNAME records (canonical name aliasing), MX records (mail exchange), and NS records (name server delegation).

### Question 5:
**How can DNS server misconfigurations lead to security vulnerabilities?**
- *Answer:* DNS server misconfigurations, such as incorrect zone settings, outdated software versions, or insecure DNSSEC configurations, can lead to DNS cache poisoning, DNS spoofing, and other security vulnerabilities.

---

## Windows API
### Question 1:
**How can knowledge of Windows API be leveraged in Red Team operations?**
- *Answer:* Understanding Windows API allows for the development of custom tools and exploits to manipulate system behavior.

### Question 2:
**What is the Windows API, and how is it used in software development?**
- *Answer:* The Windows API (Application Programming Interface) is a set of functions and data structures provided by the Windows operating system for use by applications. It allows developers to interact with the operating system and perform tasks such as file I/O, memory management, and GUI programming.

### Question 3:
**Describe the difference between the Win32 API and the .NET Framework.**
- *Answer:* The Win32 API is a native API for developing Windows applications using C/C++, while the .NET Framework is a managed framework that provides a higher-level programming interface for developing Windows applications using languages like C# and Visual Basic.NET.

### Question 4:
**What are some common security considerations when using the Windows API?**
- *Answer:* Common security considerations include input validation to prevent buffer overflows and other vulnerabilities, proper error handling to prevent information leakage, and access control to restrict privileged operations.

### Question 5:
**Can you give an example of using the Windows API to perform a common task?**
- *Answer:* here's an example of using the Windows API to create a new directory in C++:
```cpp
#include <Windows.h>
#include <iostream>
using namespace std;

int main() {
    LPCWSTR path = L"C:\\MyFolder";
    if (!CreateDirectory(path, NULL)) {
        cout << "Failed to create directory." << endl;
        return 1;
    }
    cout << "Directory created successfully." << endl;
    return 0;
}
```

## Macro Attack
### Question 1:
**What are macro attacks, and how are they typically executed?**
- *Answer:* Macro attacks involve embedding malicious code within Office documents and tricking users into enabling macros to execute the code.

### Question 2:
**What are macro-based attacks, and how do they exploit Microsoft Office applications?**
- *Answer:* Macro-based attacks involve the use of malicious macros embedded in Microsoft Office documents (e.g., Word, Excel) to execute unauthorized commands or download and execute malware on a victim's system.

### Question 3:
**How can organizations defend against macro-based attacks?**
- *Answer:* Organizations can defend against macro-based attacks by disabling macros by default, implementing security policies to restrict macro execution, and using email filtering solutions to detect and block malicious attachments.

### Question 4:
**What are some common social engineering techniques used in macro-based attacks?**
- *Answer:* Common social engineering techniques include phishing emails that trick users into enabling macros by posing as legitimate documents or enticing users with promises of rewards or urgent information.

### Question 5:
**How can users identify potentially malicious macros in Microsoft Office documents?**
- *Answer:* Users can identify potentially malicious macros by scrutinizing email attachments for suspicious content, avoiding enabling macros in documents from untrusted sources, and verifying the legitimacy of documents with the sender before opening them.

--- 

## APT Groups
### Question 1:
**What distinguishes APT groups from other threat actors?**
- *Answer:* APT groups are typically state-sponsored or highly organized cybercriminal organizations with advanced capabilities and specific objectives.

### Question 2:
**What are APT (Advanced Persistent Threat) groups, and what distinguishes them from regular cybercriminals?**
- *Answer:* APT groups are sophisticated threat actors typically associated with nation-states or well-funded organizations. They conduct long-term, targeted cyber espionage campaigns, often employing advanced tactics, techniques, and procedures (TTPs) to evade detection and maintain persistence.

### Question 3:
**Can you provide examples of well-known APT groups and their notable campaigns?**
- *Answer:* Examples of well-known APT groups include APT28 (Fancy Bear), APT29 (Cozy Bear), APT32 (OceanLotus), and APT41 (Winnti Group). Notable campaigns attributed to these groups include the DNC hack, SolarWinds supply chain attack, and Operation GhostSecret.

### Question 4:
**What motivates APT groups, and what are their primary objectives?**
- *Answer:* APT groups are often motivated by geopolitical, economic, or military objectives, including stealing intellectual property, conducting espionage, disrupting critical infrastructure, or advancing national interests.

### Question 5:
**How do organizations defend against APT group attacks?**
- *Answer:* Defending against APT group attacks requires a multi-layered security approach, including robust network perimeter defenses, endpoint protection, user education, threat intelligence sharing, and continuous monitoring for suspicious activities.

--- 

## EDR and Antivirus
### Question 1:
**How do you bypass antivirus and endpoint detection and response (EDR) solutions?**
- *Answer:* By using obfuscation techniques, modifying malware payloads, or leveraging zero-day exploits to evade detection.

### Question 2:
**What is EDR (Endpoint Detection and Response), and how does it differ from traditional antivirus solutions?**
- *Answer:* EDR is an advanced security technology that provides real-time monitoring, detection, and response capabilities on endpoints. Unlike traditional antivirus solutions, EDR solutions offer enhanced visibility into endpoint activities and behaviors, allowing for more effective threat detection and response.

### Question 3:
**What techniques can adversaries use to bypass EDR and antivirus solutions?**
- *Answer:* Adversaries can employ various techniques to bypass EDR and antivirus solutions, including code obfuscation, fileless malware, process injection, DLL hijacking, and polymorphic malware.

### Question 4:
**How can organizations enhance their EDR and antivirus defenses to mitigate bypass techniques?**
- *Answer:* Organizations can enhance their EDR and antivirus defenses by implementing security best practices such as keeping software up-to-date, using behavioral analysis and machine learning algorithms, employing endpoint detection rules based on known attack patterns, and conducting regular security assessments and threat hunting exercises.

### Question 5:
**What are some common indicators of compromise (IOCs) that organizations can use to detect EDR and antivirus bypass attempts?**
- *Answer:* Common IOCs include anomalous process behavior, unusual network traffic patterns, unauthorized file system modifications, and alerts triggered by EDR or antivirus solutions.

---

## Malware Development
### Question 1:
**What are the key steps in developing custom malware for a specific target?**
- *Answer:* Researching the target environment, designing evasion techniques, coding the malware, testing for effectiveness, and continuously refining to avoid detection.

### Question 2:
**What is malware, and what are the main categories of malware?**
- *Answer:* Malware (malicious software) is any software intentionally designed to cause harm to a computer, server, network, or user. The main categories of malware include viruses, worms, trojans, ransomware, spyware, adware, and rootkits.

### Question 3:
**Describe the malware development lifecycle and the stages involved.**
- *Answer:* The malware development lifecycle typically involves stages such as reconnaissance, weaponization, delivery, exploitation, installation, command and control (C&C), and actions on objectives (e.g., data exfiltration, system takeover).

### Question 4:
**What programming languages are commonly used for malware development, and why?**
- *Answer:* Common programming languages for malware development include C/C++, Python, PowerShell, and Assembly language. These languages offer low-level system access, flexibility, and the ability to obfuscate code to evade detection.

### Question 5:
**How can organizations defend against malware threats?**
- *Answer:* Organizations can defend against malware threats by implementing security measures such as endpoint protection, network segmentation, email filtering, user education, regular software patching, and incident response plans.

---

## System & Kernel Programming
### Question 1:
**Why is knowledge of system and kernel programming important for Red Team operations?**
- *Answer:* It allows for the development of rootkits, device drivers, and other low-level tools for exploitation and persistence.

### Question 2:
**What is system programming, and how does it differ from application programming?**
- *Answer:* System programming involves writing code that interacts directly with the operating system kernel and hardware components, often to perform low-level tasks such as device management, memory allocation, and process scheduling. In contrast, application programming focuses on developing software applications that run on top of the operating system.

### Question 3:
**Describe the role of the kernel in an operating system and its significance in system programming.**
- *Answer:* The kernel is the core component of an operating system responsible for managing system resources, providing essential services, and facilitating communication between hardware and software components. System programmers often interact with the kernel through system calls and device drivers to perform privileged operations and access hardware resources.

### Question 4:
**What programming languages are commonly used for system and kernel programming, and why?**
- *Answer:* Common languages for system and kernel programming include C, C++, and Assembly language. These languages offer low-level control over system resources, direct memory access, and the ability to write efficient, hardware-specific code.

### Question 5:
**What are some examples of system programming tasks and applications?**
- *Answer:* Examples of system programming tasks include writing device drivers, implementing file systems, developing operating system utilities, building embedded systems firmware, and creating network protocol implementations.

---

## Privilege Escalation
### Question 1:
**What methods can you employ for privilege escalation on a compromised system?**
- *Answer:* Exploiting misconfigurations, leveraging known vulnerabilities, or abusing weak permissions.

### Question 2:
**What is privilege escalation, and why is it a significant security concern?**
- *Answer:* Privilege escalation is the process of gaining higher levels of access or permissions than originally granted by exploiting vulnerabilities or misconfigurations in a system or application. It is a significant security concern because it allows attackers to bypass access controls, compromise sensitive data, and execute malicious actions with elevated privileges.

### Question 3:
**What are the main types of privilege escalation, and how do they differ?**
- *Answer:* The main types of privilege escalation are local privilege escalation (LPE) and remote privilege escalation (RPE). LPE involves elevating privileges on the local system, while RPE involves gaining elevated privileges across networked systems or services.

### Question 4:
**What are some common techniques used for privilege escalation on Windows systems?**
- *Answer:* Common techniques for privilege escalation on Windows systems include exploiting misconfigured service permissions, abusing weak user account privileges, exploiting unpatched software vulnerabilities, and bypassing User Account Control (UAC) restrictions.

### Question 5:
**How can organizations prevent privilege escalation attacks?**
- *Answer:* Organizations can prevent privilege escalation attacks by implementing security best practices such as least privilege principles, regularly patching and updating software, using strong authentication mechanisms, monitoring system logs for suspicious activity, and employing privilege management solutions.

---

## Post-exploitation (and Lateral Movement)
### Question 1:
**After gaining access to a system, what steps do you take for post-exploitation and lateral movement?**
- *Answer:* Enumerate network resources, escalate privileges, and move laterally to other systems to establish persistence and further compromise the network.

### Question 2:
**What is post-exploitation, and how does it differ from initial access?**
- *Answer:* Post-exploitation refers to the phase of a cyber attack that occurs after an attacker has gained unauthorized access to a system or network. It involves activities such as maintaining access, gathering intelligence, escalating privileges, and moving laterally within the network. In contrast, initial access focuses on the methods used to gain the initial foothold in the target environment.

### Question 3:
**What are some common post-exploitation techniques used by attackers?**
- *Answer:* Common post-exploitation techniques include establishing persistent access through backdoors or rootkits, harvesting credentials, exfiltrating sensitive data, escalating privileges, and moving laterally across networked systems to expand the attack surface.

### Question 4:
**How does lateral movement contribute to post-exploitation activities, and what are some common methods used for lateral movement?**
- *Answer:* Lateral movement involves the traversal of networked systems by an attacker to extend their reach and compromise additional resources. Common methods of lateral movement include using stolen credentials, exploiting vulnerabilities in unpatched systems, abusing trust relationships, and employing tools such as Remote Desktop Protocol (RDP) or PowerShell for remote access.

### Question 5:
**What strategies can organizations employ to detect and mitigate post-exploitation activities?**
- *Answer:* Organizations can detect and mitigate post-exploitation activities by implementing network segmentation to limit lateral movement, deploying intrusion detection and prevention systems (IDPS), monitoring system logs for suspicious behavior, conducting regular security assessments and penetration tests, and enforcing least privilege access controls.

---

## Persistence

- TBD

## Breaking Hash

- TBD

## C&C (Command and Control)

- TBD

## DLL

- TBD

## DNS Rebinding

- TBD

## LDAP

- TBD

## Evasion

- TBD

## Steganography

- TBD

## Kerberoasting and Kerberos

- TBD

## Mimikatz

- TBD

## RDP

- TBD

## NTLM

- TBD

## YARA Language

- TBD

## Windows API And DLL Difference

- TBD

## Antivirus and EDR Difference

- TBD

## NTDLL

- TBD

## Native API

- TBD

## Windows Driver

- TBD

## Tunneling

- TBD

## Shadow File

- TBD

## SAM File

- TBD

## LSA

- TBD

## LSASS

- TBD

## WDIGEST

- TBD

## CredSSP

- TBD

## MSV

- TBD

## LiveSSP

- TBD

## TSpkg

- TBD

## CredMan

- TBD

## EDR NDR XDR

- TBD

## Polymorphic Malware

- TBD

## Pass-the-Hash, Pass-the-Ticket or Build Golden Tickets

- TBD

## Firewall

- TBD

## WinDBG (Windows Debugger)

- TBD

## PE (Portable Executable)

- TBD

## ICMP

- TBD

## Major Microsoft frameworks for Windows

- TBD

## Services and Processes

- TBD

## svchost

- TBD

## CIM Class

- TBD

## CDB, NTSD, KD, Gflags, GflagsX, PE Explorer

- TBD

## Sysinternals Suite (tools)

- TBD

## Undocumented Functions

- TBD

## Process Explorer vs Process Hacker

- TBD

## CLR (Common Language Runtime)

- TBD


# Acknowledgement 

* Fazel Mohammad Ali Pour: <a href="https://github.com/EmadYaY" target="_blank">
  <img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/github.svg" alt="EmadYaY" height="30" width="40" />
</a><a href="https://twitter.com/arganexemad" target="_blank">
  <img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/twitter.svg" alt="arganexemad" height="30" width="40" />
</a><a href="https://linkedin.com/in/fazel-mohammad-ali-pour" target="_blank">
  <img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/linked-in-alt.svg" alt="fazel-mohammad-ali-pour" height="30" width="40" />
</a>

* -


Brought to you by:

<img src="https://hadess.io/wp-content/uploads/2022/04/LOGOTYPE-tag-white-.png" alt="HADESS" width="200"/>

[HADESS](https://hadess.io) performs offensive cybersecurity services through infrastructures and software that include vulnerability analysis, scenario attack planning, and implementation of custom-integrated preventive projects. We organized our activities around the prevention of corporate, industrial, and laboratory cyber threats.
