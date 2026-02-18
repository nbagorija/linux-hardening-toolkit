#!/bin/bash

#============================================
# Module: Service Audit
# Description: Audits running services,
#              autostart, cron jobs, processes
#============================================

service_audit() {
    echo -e "${CYAN}[MODULE] Аудит сервисов${NC}"
    echo ""

    #----------------------------------------
    # 1. Запущенные сервисы
    #----------------------------------------
    echo -e "${BLUE}[*] Запущенные сервисы:${NC}"
    log_result "--- Running Services ---"

    if command -v systemctl &>/dev/null; then
        RUNNING_SERVICES=$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep ".service")
        RUNNING_COUNT=$(echo "$RUNNING_SERVICES" | grep -c ".service")

        echo -e "    Запущенных сервисов: $RUNNING_COUNT"
        log_result "Running services: $RUNNING_COUNT"
        echo ""

        echo "$RUNNING_SERVICES" | while read -r line; do
            SERVICE_NAME=$(echo "$line" | awk '{print $1}')
            echo -e "    $SERVICE_NAME"
            log_result "Running: $SERVICE_NAME"
        done
    else
        echo -e "${YELLOW}    [!] systemctl не найден${NC}"
        log_result "[INFO] systemctl not available"

        # Альтернатива
        if command -v service &>/dev/null; then
            service --status-all 2>/dev/null | grep "+" | tee -a "$REPORT_FILE"
        fi
    fi
    echo ""

    #----------------------------------------
    # 2. Сервисы в автозапуске
    #----------------------------------------
    echo -e "${BLUE}[*] Сервисы в автозапуске:${NC}"
    log_result "--- Enabled Services ---"

    if command -v systemctl &>/dev/null; then
        ENABLED_SERVICES=$(systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | grep ".service")
        ENABLED_COUNT=$(echo "$ENABLED_SERVICES" | grep -c ".service")

        echo -e "    Сервисов в автозапуске: $ENABLED_COUNT"
        log_result "Enabled services: $ENABLED_COUNT"
        echo ""

        echo "$ENABLED_SERVICES" | while read -r line; do
            SERVICE_NAME=$(echo "$line" | awk '{print $1}')
            echo -e "    $SERVICE_NAME"
            log_result "Enabled: $SERVICE_NAME"
        done
    fi
    echo ""

    #----------------------------------------
    # 3. Потенциально опасные сервисы
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка потенциально опасных сервисов:${NC}"
    log_result "--- Dangerous Services Check ---"

    declare -A DANGEROUS_SERVICES
    DANGEROUS_SERVICES=(
        ["telnet.socket"]="Telnet — незашифрованный протокол"
        ["rsh.socket"]="RSH — незашифрованный удалённый shell"
        ["rlogin.socket"]="Rlogin — незашифрованный удалённый логин"
        ["rexec.socket"]="Rexec — незашифрованное удалённое выполнение"
        ["vsftpd"]="FTP — незашифрованная передача файлов"
        ["tftpd"]="TFTP — незащищённая передача файлов"
        ["xinetd"]="Xinetd — устаревший суперсервер"
        ["avahi-daemon"]="Avahi — mDNS (может быть ненужен)"
        ["cups"]="CUPS — печать (ненужен на серверах)"
        ["bluetooth"]="Bluetooth (ненужен на серверах)"
        ["isc-dhcp-server"]="DHCP сервер"
        ["named"]="DNS сервер BIND"
        ["apache2"]="Web сервер Apache"
        ["nginx"]="Web сервер Nginx"
        ["smbd"]="Samba файловый сервер"
        ["nmbd"]="Samba NetBIOS"
        ["snmpd"]="SNMP (может утечь информация)"
        ["rpcbind"]="RPC (NFS, может быть ненужен)"
        ["nfs-server"]="NFS сервер"
    )

    DANGEROUS_FOUND=0

    for service in "${!DANGEROUS_SERVICES[@]}"; do
        DESCRIPTION="${DANGEROUS_SERVICES[$service]}"

        # Проверяем запущен ли
        IS_RUNNING=$(systemctl is-active "$service" 2>/dev/null)
        IS_ENABLED=$(systemctl is-enabled "$service" 2>/dev/null)

        if [[ "$IS_RUNNING" == "active" ]]; then
            echo -e "${RED}    [!] $service — ЗАПУЩЕН${NC}"
            echo -e "${RED}        $DESCRIPTION${NC}"
            log_result "[WARNING] $service is running — $DESCRIPTION"
            DANGEROUS_FOUND=1
        elif [[ "$IS_ENABLED" == "enabled" ]]; then
            echo -e "${YELLOW}    [!] $service — в автозапуске (не запущен)${NC}"
            echo -e "${YELLOW}        $DESCRIPTION${NC}"
            log_result "[INFO] $service is enabled — $DESCRIPTION"
            DANGEROUS_FOUND=1
        fi
    done

    if [[ $DANGEROUS_FOUND -eq 0 ]]; then
        echo -e "${GREEN}    [✓] Потенциально опасных сервисов не обнаружено${NC}"
        log_result "[OK] No dangerous services detected"
    fi
    echo ""

    #----------------------------------------
    # 4. Failed сервисы
    #----------------------------------------
    echo -e "${BLUE}[*] Сервисы с ошибками:${NC}"
    log_result "--- Failed Services ---"

    if command -v systemctl &>/dev/null; then
        FAILED_SERVICES=$(systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | grep ".service")
        FAILED_COUNT=$(echo "$FAILED_SERVICES" | grep -c ".service")

        if [[ $FAILED_COUNT -gt 0 ]]; then
            echo -e "${RED}    [!] Сервисов с ошибками: $FAILED_COUNT${NC}"
            log_result "[WARNING] Failed services: $FAILED_COUNT"

            echo "$FAILED_SERVICES" | while read -r line; do
                SERVICE_NAME=$(echo "$line" | awk '{print $2}')
                echo -e "${RED}    → $SERVICE_NAME${NC}"
                log_result "Failed: $SERVICE_NAME"
            done
        else
            echo -e "${GREEN}    [✓] Сервисов с ошибками нет${NC}"
            log_result "[OK] No failed services"
        fi
    fi
    echo ""

    #----------------------------------------
    # 5. Cron задачи — системные
    #----------------------------------------
    echo -e "${BLUE}[*] Системные cron задачи:${NC}"
    log_result "--- System Cron Jobs ---"

    # /etc/crontab
    if [[ -f /etc/crontab ]]; then
        echo -e "${BLUE}    /etc/crontab:${NC}"
        CRON_ENTRIES=$(grep -v "^#" /etc/crontab | grep -v "^$" | grep -v "^SHELL" | grep -v "^PATH" | grep -v "^MAILTO")
        if [[ -n "$CRON_ENTRIES" ]]; then
            echo "$CRON_ENTRIES" | while read -r line; do
                echo -e "    $line"
                log_result "Crontab: $line"
            done
        else
            echo -e "    (пусто)"
        fi
    fi
    echo ""

    # /etc/cron.d/
    if [[ -d /etc/cron.d ]]; then
        echo -e "${BLUE}    /etc/cron.d/:${NC}"
        CRON_D_FILES=$(ls -la /etc/cron.d/ 2>/dev/null)
        CRON_D_COUNT=$(ls /etc/cron.d/ 2>/dev/null | wc -l)
        echo -e "    Файлов: $CRON_D_COUNT"
        log_result "Files in /etc/cron.d/: $CRON_D_COUNT"

        ls /etc/cron.d/ 2>/dev/null | while read -r f; do
            echo -e "    → $f"
            log_result "Cron.d file: $f"
        done
    fi
    echo ""

    # Периодические cron
    echo -e "${BLUE}    Периодические задачи:${NC}"
    for period in hourly daily weekly monthly; do
        DIR="/etc/cron.$period"
        if [[ -d "$DIR" ]]; then
            COUNT=$(ls "$DIR" 2>/dev/null | wc -l)
            echo -e "    /etc/cron.$period: $COUNT задач"
            log_result "/etc/cron.$period: $COUNT jobs"
        fi
    done
    echo ""

    #----------------------------------------
    # 6. Cron задачи — пользовательские
    #----------------------------------------
    echo -e "${BLUE}[*] Пользовательские cron задачи:${NC}"
    log_result "--- User Cron Jobs ---"

    USER_CRON_FOUND=0
    while IFS=: read -r username _ uid _ _ _ _; do
        if [[ $uid -ge 0 ]]; then
            USER_CRON=$(crontab -l -u "$username" 2>/dev/null | grep -v "^#" | grep -v "^$")
            if [[ -n "$USER_CRON" ]]; then
                echo -e "${YELLOW}    [$username]:${NC}"
                echo "$USER_CRON" | while read -r line; do
                    echo -e "    $line"
                    log_result "User cron ($username): $line"
                done
                USER_CRON_FOUND=1
                echo ""
            fi
        fi
    done < /etc/passwd

    if [[ $USER_CRON_FOUND -eq 0 ]]; then
        echo -e "${GREEN}    [✓] Пользовательских cron задач не найдено${NC}"
        log_result "[OK] No user cron jobs found"
    fi
    echo ""

    #----------------------------------------
    # 7. Systemd таймеры
    #----------------------------------------
    echo -e "${BLUE}[*] Systemd таймеры:${NC}"
    log_result "--- Systemd Timers ---"

    if command -v systemctl &>/dev/null; then
        TIMERS=$(systemctl list-timers --all --no-pager 2>/dev/null)
        TIMER_COUNT=$(systemctl list-timers --all --no-pager 2>/dev/null | grep -c "\.timer")

        echo -e "    Активных таймеров: $TIMER_COUNT"
        log_result "Active timers: $TIMER_COUNT"

        systemctl list-timers --all --no-pager 2>/dev/null | head -15 | while read -r line; do
            echo -e "    $line"
            log_result "$line"
        done

        if [[ $TIMER_COUNT -gt 15 ]]; then
            echo -e "${YELLOW}    ... показано 15 из $TIMER_COUNT${NC}"
        fi
    fi
    echo ""

    #----------------------------------------
    # 8. Процессы от root
    #----------------------------------------
    echo -e "${BLUE}[*] Процессы запущенные от root:${NC}"
    log_result "--- Root Processes ---"

    ROOT_PROCS=$(ps aux 2>/dev/null | awk '$1 == "root" {print $0}')
    ROOT_PROC_COUNT=$(echo "$ROOT_PROCS" | wc -l)

    echo -e "    Процессов от root: $ROOT_PROC_COUNT"
    log_result "Root processes: $ROOT_PROC_COUNT"

    # Показываем топ по CPU
    echo ""
    echo -e "${BLUE}    Топ 10 root процессов по CPU:${NC}"
    ps aux --sort=-%cpu 2>/dev/null | awk '$1 == "root"' | head -10 | while read -r line; do
        echo -e "    $line"
        log_result "$line"
    done
    echo ""

    #----------------------------------------
    # 9. Процессы от обычных пользователей
    #----------------------------------------
    echo -e "${BLUE}[*] Процессы от обычных пользователей:${NC}"
    log_result "--- User Processes ---"

    NON_SYSTEM_PROCS=$(ps aux 2>/dev/null | awk '$1 != "root" && NR > 1' | awk '{print $1}' | sort -u)

    echo "$NON_SYSTEM_PROCS" | while read -r user; do
        if [[ -n "$user" ]]; then
            USER_PROC_COUNT=$(ps aux 2>/dev/null | awk -v u="$user" '$1 == u' | wc -l)
            echo -e "    $user: $USER_PROC_COUNT процессов"
            log_result "User $user: $USER_PROC_COUNT processes"
        fi
    done
    echo ""

    #----------------------------------------
    # 10. Подозрительные процессы
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка подозрительных процессов:${NC}"
    log_result "--- Suspicious Processes Check ---"

    SUSPICIOUS_FOUND=0

    # Процессы с удалённых бинарников
    DELETED_PROCS=$(ls -la /proc/*/exe 2>/dev/null | grep "(deleted)")
    if [[ -n "$DELETED_PROCS" ]]; then
        echo -e "${RED}    [!] Процессы с удалёнными бинарниками:${NC}"
        echo "$DELETED_PROCS" | while read -r line; do
            PID=$(echo "$line" | grep -oP '/proc/\K[0-9]+')
            PROC_NAME=$(ps -p "$PID" -o comm= 2>/dev/null)
            echo -e "${RED}    → PID $PID ($PROC_NAME) — бинарник удалён!${NC}"
            log_result "[CRITICAL] Deleted binary: PID $PID ($PROC_NAME)"
        done
        SUSPICIOUS_FOUND=1
    fi

    # Процессы из /tmp или /dev/shm
    TMP_PROCS=$(ls -la /proc/*/exe 2>/dev/null | grep -E "/tmp/|/dev/shm/|/var/tmp/")
    if [[ -n "$TMP_PROCS" ]]; then
        echo -e "${RED}    [!] Процессы запущенные из /tmp или /dev/shm:${NC}"
        echo "$TMP_PROCS" | while read -r line; do
            echo -e "${RED}    → $line${NC}"
            log_result "[CRITICAL] Process from tmp: $line"
        done
        SUSPICIOUS_FOUND=1
    fi

    # Криптомайнеры
    MINERS=$(ps aux 2>/dev/null | grep -iE "xmrig|minerd|cpuminer|stratum|cryptonight|monero" | grep -v grep)
    if [[ -n "$MINERS" ]]; then
        echo -e "${RED}    [!] Возможные криптомайнеры обнаружены!${NC}"
        echo "$MINERS" | while read -r line; do
            echo -e "${RED}    → $line${NC}"
            log_result "[CRITICAL] Possible cryptominer: $line"
        done
        SUSPICIOUS_FOUND=1
    fi

    # Реверс-шеллы
    REV_SHELLS=$(ps aux 2>/dev/null | grep -iE "nc -e|ncat -e|bash -i|/dev/tcp|python.*socket|perl.*socket" | grep -v grep)
    if [[ -n "$REV_SHELLS" ]]; then
        echo -e "${RED}    [!] Возможные реверс-шеллы обнаружены!${NC}"
        echo "$REV_SHELLS" | while read -r line; do
            echo -e "${RED}    → $line${NC}"
            log_result "[CRITICAL] Possible reverse shell: $line"
        done
        SUSPICIOUS_FOUND=1
    fi

    if [[ $SUSPICIOUS_FOUND -eq 0 ]]; then
        echo -e "${GREEN}    [✓] Подозрительных процессов не обнаружено${NC}"
        log_result "[OK] No suspicious processes detected"
    fi
    echo ""

    echo -e "${GREEN}[✓] Аудит сервисов завершён${NC}"
}

# Запуск
service_audit
