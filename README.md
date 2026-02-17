# linux-hardening-toolkit
Automated Linux security auditing and hardening tool based on CIS Benchmarks

## 📋 Description

This toolkit performs comprehensive security audits of Linux systems and provides
hardening recommendations. It is designed for system administrators and security
professionals who want to quickly assess and improve the security posture of
their Linux servers.

## 🚀 Features

- **System Information Gathering** — OS, kernel, hardware details
- **User Account Audit** — password policies, inactive accounts, sudo access
- **SSH Hardening** — configuration analysis and recommendations
- **Firewall Audit** — iptables/nftables rules review
- **File Permissions Check** — SUID/SGID, world-writable files
- **Network Audit** — open ports, active connections
- **Service Audit** — running services, unnecessary daemons
- **Logging Audit** — syslog, audit daemon configuration

## 📦 Installation

```bash
git clone https://github.com/nbagorija/linux-hardening-toolkit.git
cd linux-hardening-toolkit
chmod +x main.sh modules/*.sh


## 🔧 Usage

```bash
sudo ./main.sh

## Menu Options

- 1	Full security audit
- 2	System information
- 3	User audit
- 4	SSH audit
- 5	Firewall audit
- 6	File permissions check
- 7	Network audit
- 8	Service audit
- 9	Logging audit
- 0	Exit

## 🖥️ Requirements

- Linux (Debian/Ubuntu/Kali)
- Root privileges
- Bash 4.0+

## ⚠️ Disclaimer

This tool is intended for authorized security auditing only.
Always obtain proper authorization before running security tools
on any system. The author is not responsible for any misuse.

## 📄 License

This project is licensed under the MIT License — see the LICENSE file.

## 👤 Author

nbagorija - Github
