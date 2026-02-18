# 🛡️ CIS Benchmarks Checklist for Linux

Security checklist based on [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks).

---

## 1. System Configuration

| # | Check | Status | Module |
|---|-------|--------|--------|
| 1.1 | Ensure system is up to date | ⬜ | 01_system_info |
| 1.2 | Ensure NTP is configured | ⬜ | 01_system_info |
| 1.3 | Ensure /tmp is separate partition | ⬜ | 05_file_permissions |
| 1.4 | Ensure /tmp has nosuid, noexec | ⬜ | 05_file_permissions |

## 2. User Accounts

| # | Check | Status | Module |
|---|-------|--------|--------|
| 2.1 | Ensure only root has UID 0 | ⬜ | 02_user_audit |
| 2.2 | Ensure no accounts have empty passwords | ⬜ | 02_user_audit |
| 2.3 | Ensure PASS_MAX_DAYS <= 90 | ⬜ | 02_user_audit |
| 2.4 | Ensure PASS_MIN_DAYS >= 7 | ⬜ | 02_user_audit |
| 2.5 | Ensure PASS_MIN_LEN >= 14 | ⬜ | 02_user_audit |
| 2.6 | Ensure sudo is configured properly | ⬜ | 02_user_audit |
| 2.7 | Ensure no NOPASSWD in sudoers | ⬜ | 02_user_audit |
| 2.8 | Ensure inactive accounts are locked | ⬜ | 02_user_audit |

## 3. SSH Configuration

| # | Check | Status | Module |
|---|-------|--------|--------|
| 3.1 | Ensure SSH Protocol is 2 | ⬜ | 03_ssh_hardening |
| 3.2 | Ensure PermitRootLogin is no | ⬜ | 03_ssh_hardening |
| 3.3 | Ensure PasswordAuthentication is no | ⬜ | 03_ssh_hardening |
| 3.4 | Ensure PermitEmptyPasswords is no | ⬜ | 03_ssh_hardening |
| 3.5 | Ensure MaxAuthTries <= 4 | ⬜ | 03_ssh_hardening |
| 3.6 | Ensure ClientAliveInterval is set | ⬜ | 03_ssh_hardening |
| 3.7 | Ensure X11Forwarding is disabled | ⬜ | 03_ssh_hardening |
| 3.8 | Ensure AllowUsers/AllowGroups is set | ⬜ | 03_ssh_hardening |
| 3.9 | Ensure SSH port is non-default | ⬜ | 03_ssh_hardening |
| 3.10 | Ensure SSH key authentication is used | ⬜ | 03_ssh_hardening |

## 4. Firewall

| # | Check | Status | Module |
|---|-------|--------|--------|
| 4.1 | Ensure firewall is active | ⬜ | 04_firewall |
| 4.2 | Ensure default deny policy (INPUT) | ⬜ | 04_firewall |
| 4.3 | Ensure default deny policy (FORWARD) | ⬜ | 04_firewall |
| 4.4 | Ensure loopback traffic is allowed | ⬜ | 04_firewall |
| 4.5 | Ensure unnecessary ports are closed | ⬜ | 04_firewall |
| 4.6 | Ensure IPv4 forwarding is disabled | ⬜ | 04_firewall |

## 5. File Permissions

| # | Check | Status | Module |
|---|-------|--------|--------|
| 5.1 | Ensure /etc/passwd permissions (644) | ⬜ | 05_file_permissions |
| 5.2 | Ensure /etc/shadow permissions (640) | ⬜ | 05_file_permissions |
| 5.3 | Ensure /etc/group permissions (644) | ⬜ | 05_file_permissions |
| 5.4 | Ensure no world-writable files | ⬜ | 05_file_permissions |
| 5.5 | Ensure no unowned files | ⬜ | 05_file_permissions |
| 5.6 | Ensure SUID/SGID files are reviewed | ⬜ | 05_file_permissions |
| 5.7 | Ensure sticky bit on world-writable dirs | ⬜ | 05_file_permissions |
| 5.8 | Ensure home dirs permissions <= 750 | ⬜ | 05_file_permissions |
| 5.9 | Ensure umask is 027 or more restrictive | ⬜ | 05_file_permissions |

## 6. Network

| # | Check | Status | Module |
|---|-------|--------|--------|
| 6.1 | Ensure IP forwarding is disabled | ⬜ | 06_network_audit |
| 6.2 | Ensure source routing is disabled | ⬜ | 06_network_audit |
| 6.3 | Ensure ICMP redirects are not accepted | ⬜ | 06_network_audit |
| 6.4 | Ensure suspicious packets are logged | ⬜ | 06_network_audit |
| 6.5 | Ensure TCP SYN cookies are enabled | ⬜ | 06_network_audit |
| 6.6 | Ensure no promiscuous interfaces | ⬜ | 06_network_audit |
| 6.7 | Ensure no duplicate MAC addresses | ⬜ | 06_network_audit |
| 6.8 | Ensure no suspicious connections | ⬜ | 06_network_audit |

## 7. Services

| # | Check | Status | Module |
|---|-------|--------|--------|
| 7.1 | Ensure unnecessary services are disabled | ⬜ | 07_service_audit |
| 7.2 | Ensure no telnet/rsh/rlogin | ⬜ | 07_service_audit |
| 7.3 | Ensure cron jobs are reviewed | ⬜ | 07_service_audit |
| 7.4 | Ensure no suspicious processes | ⬜ | 07_service_audit |
| 7.5 | Ensure no cryptominers running | ⬜ | 07_service_audit |
| 7.6 | Ensure no reverse shells | ⬜ | 07_service_audit |
| 7.7 | Ensure no processes from /tmp | ⬜ | 07_service_audit |

## 8. Logging

| # | Check | Status | Module |
|---|-------|--------|--------|
| 8.1 | Ensure syslog is running | ⬜ | 08_logging |
| 8.2 | Ensure journald is configured | ⬜ | 08_logging |
| 8.3 | Ensure auditd is installed and running | ⬜ | 08_logging |
| 8.4 | Ensure audit rules are configured | ⬜ | 08_logging |
| 8.5 | Ensure log rotation is configured | ⬜ | 08_logging |
| 8.6 | Ensure remote logging is configured | ⬜ | 08_logging |
| 8.7 | Ensure log file permissions are correct | ⬜ | 08_logging |
| 8.8 | Ensure logs are not empty | ⬜ | 08_logging |

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Pass |
| ❌ | Fail |
| ⚠️ | Warning |
| ⬜ | Not checked |

---

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-123](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [DISA STIG](https://public.cyber.mil/stigs/)
