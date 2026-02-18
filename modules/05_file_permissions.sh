#!/bin/bash

#============================================
# Module: File Permissions Audit
# Description: Checks file permissions,
#              SUID/SGID, world-writable files
#============================================

file_permissions_audit() {
    echo -e "${CYAN}[MODULE] Проверка прав файлов${NC}"
    echo ""

    #----------------------------------------
    # 1. Критические системные файлы
    #----------------------------------------
    echo -e "${BLUE}[*] Права на критические файлы:${NC}"
    log_result "--- Critical File Permissions ---"

    declare -A EXPECTED_PERMS
    EXPECTED_PERMS=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/group"]="644"
        ["/etc/gshadow"]="640"
        ["/etc/sudoers"]="440"
        ["/etc/ssh/sshd_config"]="600"
        ["/etc/crontab"]="600"
        ["/etc/hosts.allow"]="644"
        ["/etc/hosts.deny"]="644"
        ["/boot/grub/grub.cfg"]="400"
    )

    for filepath in "${!EXPECTED_PERMS[@]}"; do
        if [[ -f "$filepath" ]]; then
            ACTUAL_PERMS=$(stat -c "%a" "$filepath")
            EXPECTED="${EXPECTED_PERMS[$filepath]}"
            OWNER=$(stat -c "%U:%G" "$filepath")

            if [[ "$ACTUAL_PERMS" == "$EXPECTED" ]]; then
                echo -e "${GREEN}    [✓] $filepath — $ACTUAL_PERMS ($OWNER)${NC}"
                log_result "[OK] $filepath: $ACTUAL_PERMS ($OWNER)"
            else
                echo -e "${RED}    [!] $filepath — $ACTUAL_PERMS (ожидается $EXPECTED) ($OWNER)${NC}"
                log_result "[WARNING] $filepath: $ACTUAL_PERMS (expected $EXPECTED) ($OWNER)"
            fi
        else
            echo -e "${YELLOW}    [—] $filepath — не найден${NC}"
            log_result "[INFO] $filepath: not found"
        fi
    done
    echo ""

    #----------------------------------------
    # 2. SUID файлы
    #----------------------------------------
    echo -e "${BLUE}[*] Файлы с SUID битом:${NC}"
    log_result "--- SUID Files ---"

    # Известные легитимные SUID файлы
    KNOWN_SUID=(
        "/usr/bin/sudo"
        "/usr/bin/su"
        "/usr/bin/passwd"
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/usr/bin/gpasswd"
        "/usr/bin/newgrp"
        "/usr/bin/mount"
        "/usr/bin/umount"
        "/usr/bin/fusermount"
        "/usr/bin/fusermount3"
        "/usr/bin/pkexec"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/openssh/ssh-keysign"
        "/usr/libexec/polkit-agent-helper-1"
    )

    echo -e "${YELLOW}    Поиск SUID файлов (может занять время)...${NC}"

    SUID_FILES=$(find / -perm -4000 -type f 2>/dev/null)
    SUID_COUNT=$(echo "$SUID_FILES" | grep -c .)

    echo -e "    Найдено SUID файлов: $SUID_COUNT"
    log_result "Total SUID files: $SUID_COUNT"

    # Проверяем каждый SUID файл
    SUSPICIOUS_SUID=0
    echo "$SUID_FILES" | while read -r suid_file; do
        if [[ -z "$suid_file" ]]; then
            continue
        fi

        # Проверяем в списке известных
        IS_KNOWN=0
        for known in "${KNOWN_SUID[@]}"; do
            if [[ "$suid_file" == "$known" ]]; then
                IS_KNOWN=1
                break
            fi
        done

        PERMS=$(stat -c "%a" "$suid_file" 2>/dev/null)
        OWNER=$(stat -c "%U:%G" "$suid_file" 2>/dev/null)

        if [[ $IS_KNOWN -eq 1 ]]; then
            echo -e "${GREEN}    [✓] $suid_file ($PERMS, $OWNER)${NC}"
            log_result "[OK] SUID: $suid_file ($PERMS, $OWNER)"
        else
            echo -e "${RED}    [!] $suid_file ($PERMS, $OWNER) — НЕСТАНДАРТНЫЙ${NC}"
            log_result "[WARNING] Unusual SUID: $suid_file ($PERMS, $OWNER)"
        fi
    done
    echo ""

    #----------------------------------------
    # 3. SGID файлы
    #----------------------------------------
    echo -e "${BLUE}[*] Файлы с SGID битом:${NC}"
    log_result "--- SGID Files ---"

    echo -e "${YELLOW}    Поиск SGID файлов...${NC}"

    SGID_FILES=$(find / -perm -2000 -type f 2>/dev/null)
    SGID_COUNT=$(echo "$SGID_FILES" | grep -c .)

    echo -e "    Найдено SGID файлов: $SGID_COUNT"
    log_result "Total SGID files: $SGID_COUNT"

    echo "$SGID_FILES" | head -15 | while read -r sgid_file; do
        if [[ -n "$sgid_file" ]]; then
            PERMS=$(stat -c "%a" "$sgid_file" 2>/dev/null)
            OWNER=$(stat -c "%U:%G" "$sgid_file" 2>/dev/null)
            echo -e "    $sgid_file ($PERMS, $OWNER)"
            log_result "SGID: $sgid_file ($PERMS, $OWNER)"
        fi
    done

    if [[ $SGID_COUNT -gt 15 ]]; then
        echo -e "${YELLOW}    ... показано 15 из $SGID_COUNT${NC}"
    fi
    echo ""

    #----------------------------------------
    # 4. World-writable файлы
    #----------------------------------------
    echo -e "${BLUE}[*] World-writable файлы:${NC}"
    log_result "--- World-Writable Files ---"

    echo -e "${YELLOW}    Поиск world-writable файлов...${NC}"

    WW_FILES=$(find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null)
    WW_COUNT=$(echo "$WW_FILES" | grep -c . 2>/dev/null)

    if [[ $WW_COUNT -gt 0 && -n "$WW_FILES" ]]; then
        echo -e "${RED}    [!] Найдено world-writable файлов: $WW_COUNT${NC}"
        log_result "[WARNING] World-writable files found: $WW_COUNT"

        echo "$WW_FILES" | head -10 | while read -r ww_file; do
            if [[ -n "$ww_file" ]]; then
                PERMS=$(stat -c "%a" "$ww_file" 2>/dev/null)
                OWNER=$(stat -c "%U:%G" "$ww_file" 2>/dev/null)
                echo -e "${RED}    → $ww_file ($PERMS, $OWNER)${NC}"
                log_result "World-writable: $ww_file ($PERMS, $OWNER)"
            fi
        done

        if [[ $WW_COUNT -gt 10 ]]; then
            echo -e "${YELLOW}    ... показано 10 из $WW_COUNT${NC}"
        fi
    else
        echo -e "${GREEN}    [✓] World-writable файлов не найдено${NC}"
        log_result "[OK] No world-writable files found"
    fi
    echo ""

    #----------------------------------------
    # 5. World-writable директории без sticky bit
    #----------------------------------------
    echo -e "${BLUE}[*] World-writable директории без sticky bit:${NC}"
    log_result "--- World-Writable Dirs without Sticky Bit ---"

    WW_DIRS=$(find / -xdev -type d -perm -0002 ! -perm -1000 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null)
    WW_DIR_COUNT=$(echo "$WW_DIRS" | grep -c . 2>/dev/null)

    if [[ $WW_DIR_COUNT -gt 0 && -n "$WW_DIRS" ]]; then
        echo -e "${RED}    [!] Найдено директорий без sticky bit: $WW_DIR_COUNT${NC}"
        log_result "[WARNING] World-writable dirs without sticky bit: $WW_DIR_COUNT"

        echo "$WW_DIRS" | while read -r ww_dir; do
            if [[ -n "$ww_dir" ]]; then
                echo -e "${RED}    → $ww_dir${NC}"
                echo -e "${YELLOW}      Исправить: chmod +t $ww_dir${NC}"
                log_result "No sticky bit: $ww_dir"
            fi
        done
    else
        echo -e "${GREEN}    [✓] Все world-writable директории имеют sticky bit${NC}"
        log_result "[OK] All world-writable dirs have sticky bit"
    fi
    echo ""

    #----------------------------------------
    # 6. Файлы без владельца
    #----------------------------------------
    echo -e "${BLUE}[*] Файлы без владельца:${NC}"
    log_result "--- Unowned Files ---"

    echo -e "${YELLOW}    Поиск файлов без владельца...${NC}"

    NOUSER=$(find / -xdev -nouser ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null)
    NOGROUP=$(find / -xdev -nogroup ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null)

    NOUSER_COUNT=$(echo "$NOUSER" | grep -c . 2>/dev/null)
    NOGROUP_COUNT=$(echo "$NOGROUP" | grep -c . 2>/dev/null)

    if [[ $NOUSER_COUNT -gt 0 && -n "$NOUSER" ]]; then
        echo -e "${YELLOW}    [!] Файлов без пользователя: $NOUSER_COUNT${NC}"
        log_result "[WARNING] Files without owner: $NOUSER_COUNT"
        echo "$NOUSER" | head -5 | while read -r f; do
            echo -e "    → $f"
            log_result "No owner: $f"
        done
    else
        echo -e "${GREEN}    [✓] Файлов без пользователя не найдено${NC}"
        log_result "[OK] No unowned files"
    fi

    if [[ $NOGROUP_COUNT -gt 0 && -n "$NOGROUP" ]]; then
        echo -e "${YELLOW}    [!] Файлов без группы: $NOGROUP_COUNT${NC}"
        log_result "[WARNING] Files without group: $NOGROUP_COUNT"
        echo "$NOGROUP" | head -5 | while read -r f; do
            echo -e "    → $f"
            log_result "No group: $f"
        done
    else
        echo -e "${GREEN}    [✓] Файлов без группы не найдено${NC}"
        log_result "[OK] No files without group"
    fi
    echo ""

    #----------------------------------------
    # 7. Права на домашние директории
    #----------------------------------------
    echo -e "${BLUE}[*] Права на домашние директории:${NC}"
    log_result "--- Home Directory Permissions ---"

    while IFS=: read -r username _ uid _ _ homedir _; do
        if [[ $uid -ge 1000 && $uid -lt 65534 && -d "$homedir" ]]; then
            PERMS=$(stat -c "%a" "$homedir")
            OWNER=$(stat -c "%U:%G" "$homedir")

            if [[ "$PERMS" -le 750 ]]; then
                echo -e "${GREEN}    [✓] $homedir — $PERMS ($OWNER)${NC}"
                log_result "[OK] $homedir: $PERMS ($OWNER)"
            else
                echo -e "${RED}    [!] $homedir — $PERMS ($OWNER) — слишком открыт!${NC}"
                echo -e "${YELLOW}        Рекомендация: chmod 750 $homedir${NC}"
                log_result "[WARNING] $homedir: $PERMS too permissive ($OWNER)"
            fi
        fi
    done < /etc/passwd
    echo ""

    #----------------------------------------
    # 8. Проверка umask
    #----------------------------------------
    echo -e "${BLUE}[*] Umask:${NC}"
    log_result "--- Umask Check ---"

    CURRENT_UMASK=$(umask)
    echo -e "    Текущий umask: $CURRENT_UMASK"
    log_result "Current umask: $CURRENT_UMASK"

    if [[ "$CURRENT_UMASK" == "0027" || "$CURRENT_UMASK" == "0077" ]]; then
        echo -e "${GREEN}    [✓] Umask безопасен${NC}"
        log_result "[OK] Umask is secure"
    elif [[ "$CURRENT_UMASK" == "0022" ]]; then
        echo -e "${YELLOW}    [!] Umask 0022 — стандартный, но не самый безопасный${NC}"
        echo -e "${YELLOW}        Рекомендация: umask 0027${NC}"
        log_result "[WARNING] Umask 0022 — consider 0027"
    else
        echo -e "${RED}    [!] Umask $CURRENT_UMASK — может быть небезопасен${NC}"
        log_result "[WARNING] Umask $CURRENT_UMASK may be insecure"
    fi
    echo ""

    #----------------------------------------
    # 9. Проверка /tmp
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка /tmp:${NC}"
    log_result "--- /tmp Check ---"

    TMP_PERMS=$(stat -c "%a" /tmp)
    echo -e "    Права /tmp: $TMP_PERMS"
    log_result "/tmp permissions: $TMP_PERMS"

    if [[ "$TMP_PERMS" == "1777" ]]; then
        echo -e "${GREEN}    [✓] /tmp имеет sticky bit${NC}"
        log_result "[OK] /tmp has sticky bit"
    else
        echo -e "${RED}    [!] /tmp без sticky bit!${NC}"
        echo -e "${YELLOW}        Исправить: chmod 1777 /tmp${NC}"
        log_result "[CRITICAL] /tmp missing sticky bit"
    fi

    # Проверяем отдельный раздел для /tmp
    if mount | grep -q " /tmp "; then
        echo -e "${GREEN}    [✓] /tmp — отдельный раздел${NC}"
        log_result "[OK] /tmp is a separate partition"

        # Проверяем опции монтирования
        TMP_MOUNT=$(mount | grep " /tmp ")
        if echo "$TMP_MOUNT" | grep -q "nosuid"; then
            echo -e "${GREEN}    [✓] /tmp имеет nosuid${NC}"
        else
            echo -e "${YELLOW}    [!] /tmp без nosuid${NC}"
            log_result "[WARNING] /tmp missing nosuid"
        fi

        if echo "$TMP_MOUNT" | grep -q "noexec"; then
            echo -e "${GREEN}    [✓] /tmp имеет noexec${NC}"
        else
            echo -e "${YELLOW}    [!] /tmp без noexec${NC}"
            log_result "[WARNING] /tmp missing noexec"
        fi
    else
        echo -e "${YELLOW}    [!] /tmp не на отдельном разделе${NC}"
        echo -e "${YELLOW}        Рекомендация: выделить /tmp на отдельный раздел${NC}"
        log_result "[WARNING] /tmp is not a separate partition"
    fi
    echo ""

    echo -e "${GREEN}[✓] Проверка прав файлов завершена${NC}"
}

# Запуск
file_permissions_audit
