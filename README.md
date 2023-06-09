<h1 align="center">「😈」About D3m0n1z3d Sh3ll</h1>

<p align="center"><img src="banner.png"></p>

DemonizedShell is a Tool to gain persistence on linux systems

### Install

```
git clone https://github.com/MatheuZSecurity/D3m0nz1n3dShell.git
cd D3m0nz1n3dShell
chmod +x demonizedshell.sh
sudo ./demonizedshell.sh
```

### One-Liner Install

```
curl -L https://github.com/MatheuZSecurity/D3m0n1z3dShell/archive/main.tar.gz | tar xz && cd D3m0n1z3dShell-main && sudo bash install.sh
```



### Demonized Features

* Auto Generate SSH keypair for all users
* APT Persistence 
* Crontab Persistence
* Systemd User level
* Systemd Root Level
* Bashrc Persistence
* Privileged user & SUID bash
* LKM Rootkit Modified, Bypassing rkhunter & chkrootkit
* LKM Rootkit With file encoder. persistent icmp backdoor and others features.
* ICMP Backdoor 
* LD_PRELOAD Setup PrivEsc
* Static Binaries For Process Monitoring, Dump credentials, Enumeration, Trolling and Others Binaries.

#### Auto Generate SSH keypair for all users:

This feature automatically generates SSH key pairs (public and private keys) for all users on a system. SSH keys are used for secure authentication and communication between systems.

#### APT Persistence:

This feature ensures persistence of malicious software installed through the Advanced Package Tool (APT) on Debian-based Linux systems. It allows the attacker's code or malware to remain installed even after system reboots or updates.

#### Crontab Persistence:

Crontab is a utility that allows users to schedule tasks or scripts to run at specific intervals. Crontab persistence involves adding malicious scripts or commands to the crontab configuration to execute them automatically at specified times or intervals.

#### Systemd User level:

Systemd is a popular system and service manager for many Linux distributions. Systemd user-level persistence involves setting up malicious services or scripts at the user level to gain persistence and execute unauthorized actions.

#### Systemd Root Level:

Similar to systemd user-level persistence, systemd root-level persistence involves setting up malicious services or scripts at the root level, allowing the attacker to gain elevated privileges and maintain persistence on the system.

#### Bashrc Persistence:

The bashrc file contains shell configurations and commands that are executed when a user starts a new shell session. Bashrc persistence involves adding malicious commands or scripts to the bashrc file, ensuring that they run every time a user opens a shell, thus maintaining persistence.

#### Privileged user & SUID bash:

Privileged users have administrative or root-level access to a system. SUID (Set User ID) is a permission that allows users to execute a file with the permissions of the file's owner, regardless of the user's actual permissions. Combining privileged user access with SUID bash allows an attacker to execute commands with elevated privileges.

#### LKM Rootkit Modified, Bypassing rkhunter & chkrootkit:

LKM (Loadable Kernel Module) rootkits are malicious modules that can be loaded into the kernel of an operating system, allowing attackers to gain unauthorized access and control over the system. Modifying an LKM rootkit to bypass security tools like rkhunter and chkrootkit makes it more difficult for system administrators to detect and remove the rootkit.

#### LKM Rootkit With file encoder, persistent ICMP backdoor, and other features:

This feature involves enhancing an LKM rootkit with additional functionality. It includes a file encoder to obfuscate the rootkit code, a persistent ICMP (Internet Control Message Protocol) backdoor for remote access, and potentially other undisclosed features designed to enable unauthorized actions on the compromised system.

#### ICMP Backdoor:

ICMP backdoor refers to the use of ICMP packets for establishing a covert communication channel between an attacker-controlled system and a compromised system. ICMP is typically used for network diagnostics, but an attacker can manipulate it to create a hidden communication channel, bypassing traditional network security measures.

#### LD_PRELOAD Setup PrivEsc:

The LD_PRELOAD environment variable is used to specify a shared library that should be loaded before all others when executing a program. LD_PRELOAD setup for privilege escalation (PrivEsc) involves using a malicious shared library to override system functions or gain unauthorized access to resources, potentially leading to elevated privileges.

#### Static Binaries for Process Monitoring, Dump Credentials, Enumeration, Trolling, and other Binaries:

Static binaries are compiled executables that include all the necessary libraries and dependencies, making them self-contained and portable. This feature involves creating custom static binaries with various functionalities, such as process monitoring, credential dumping, system enumeration, trolling, and potentially other undisclosed actions.

### Pending Features

* [ ] LD_PRELOAD Rootkit
* [ ] Process Injection
* [x] install for example: curl github.com/test/test/demonized.sh | bash
* [ ] Intercept Syscall Write from a file

And other types of features that will come in the future.

## Contribution

If you want to contribute and help with the tool, please contact me.

## Note

> We are not responsible for any damage caused by this tool, use the tool intelligently and for educational purposes only.
