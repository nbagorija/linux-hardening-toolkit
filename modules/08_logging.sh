#!/bin/bash

#============================================
# Module: Logging Audit
# Description: Audits logging configuration,
#              log files, audit daemon, rotation
#============================================

logging_audit() {
    echo -e "${CYAN}[MODULE] Аудит логирования${NC}"
    echo ""

    #----------------------------------------
    # 1. Syslog сервис
    #----------------------------------------
    echo -e "${BLUE}[*] Статус syslog:${NC}"
    log_result "--- Syslog Status ---"

    SYSLOG_FOUND=0

    # rsyslog
    if command -v rsyslogd &>/dev/null; then
        SYSLOG_FOUND=1
        echo -e "    rsyslog найден"
        log_result "rsyslog: found"

        if systemctl is-active --quiet rsyslog 2>/dev/null; then
            echo -e "${GREEN}    [✓] rsyslog запущен${NC}"
            log_result "[OK] rsyslog is running"
        else
            echo -e "${RED}    [!] rsyslog НЕ запущен!${NC}"
            log_result "[CRITICAL] rsyslog is not running"
        fi

        if systemctl is-enabled --quiet rsyslog 2>/dev/null; then
            echo -e "${GREEN}    [✓] rsyslog в автозапуске${NC}"
            log_result "[OK] rsyslog is enabled"
        else
            echo -e "${RED}    [!] rsyslog НЕ в автозапуске!${NC}"
            echo -e "${YELLOW}        Рекомендация: systemctl enable rsyslog${NC}"
            log_result "[WARNING] rsyslog is not enabled"
        fi
    fi

    # syslog-ng
    if command -v syslog-ng &>/dev/null; then
        SYSLOG_FOUND=1
        echo -e "    syslog-ng найден"
        log_result "syslog-ng: found"

        if systemctl is-active --quiet syslog-ng 2>/dev/null; then
            echo -e "${GREEN}    [✓] syslog-ng запущен${NC}"
            log_result "[OK] syslog-ng is running"
        else
            echo -e "${RED}    [!] syslog-ng НЕ запущен!${NC}"
            log_result "[CRITICAL] syslog-ng is not running"
        fi
    fi

    if [[ $SYSLOG_FOUND -eq 0 ]]; then
        echo -e "${RED}    [!] Syslog сервис не найден!${NC}"
        echo -e "${YELLOW}        Рекомендация: установить rsyslog${NC}"
        log_result "[CRITICAL] No syslog service found"
    fi
    echo ""

    #----------------------------------------
    # 2. Journald
    #----------------------------------------
    echo -e "${BLUE}[*] Статус journald:${NC}"
    log_result "--- Journald Status ---"

    if command -v journalctl &>/dev/null; then
        if systemctl is-active --quiet systemd-journald 2>/dev/null; then
            echo -e "${GREEN}    [✓] journald запущен${NC}"
            log_result "[OK] journald is running"

            # Настройки journald
            JOURNALD_CONF="/etc/systemd/journald.conf"
            if [[ -f "$JOURNALD_CONF" ]]; then
                echo -e "${BLUE}    Настройки journald:${NC}"

                # Storage
                STORAGE=$(grep "^Storage=" "$JOURNALD_CONF" 2>/dev/null | cut -d= -f2)
                STORAGE=${STORAGE:-"auto (default)"}
                echo -e "    Storage: $STORAGE"
                log_result "Journald Storage: $STORAGE"

                if [[ "$STORAGE" == "volatile" ]]; then
                    echo -e "${YELLOW}    [!] Логи хранятся только в RAM!${NC}"
                    echo -e "${YELLOW}        Рекомендация: Storage=persistent${NC}"
                    log_result "[WARNING] Journald storage is volatile"
                fi

                # Compress
                COMPRESS=$(grep "^Compress=" "$JOURNALD_CONF" 2>/dev/null | cut -d= -f2)
                COMPRESS=${COMPRESS:-"yes (default)"}
                echo -e "    Compress: $COMPRESS"
                log_result "Journald Compress: $COMPRESS"

                # MaxRetentionSec
                RETENTION=$(grep "^MaxRetentionSec=" "$JOURNALD_CONF" 2>/dev/null | cut -d= -f2)
                RETENTION=${RETENTION:-"not set (default)"}
                echo -e "    MaxRetentionSec: $RETENTION"
                log_result "Journald MaxRetentionSec: $RETENTION"

                # SystemMaxUse
                MAX_USE=$(grep "^SystemMaxUse=" "$JOURNALD_CONF" 2>/dev/null | cut -d= -f2)
                MAX_USE=${MAX_USE:-"not set (default)"}
                echo -e "    SystemMaxUse: $MAX_USE"
                log_result "Journald SystemMaxUse: $MAX_USE"

                # ForwardToSyslog
                FWD_SYSLOG=$(grep "^ForwardToSyslog=" "$JOURNALD_CONF" 2>/dev/null | cut -d= -f2)
                FWD_SYSLOG=${FWD_SYSLOG:-"yes (default)"}
                echo -e "    ForwardToSyslog: $FWD_SYSLOG"
                log_result "Journald ForwardToSyslog: $FWD_SYSLOG"
            fi

            # Размер журнала
            echo ""
            JOURNAL_SIZE=$(journalctl --disk-usage 2>/dev/null | awk '{print $7, $8}')
            echo -e "    Размер журнала: $JOURNAL_SIZE"
            log_result "Journal size: $JOURNAL_SIZE"

        else
            echo -e "${RED}    [!] journald НЕ запущен!${NC}"
            log_result "[CRITICAL] journald is not running"
        fi
    else
        echo -e "${YELLOW}    [!] journalctl не найден${NC}"
        log_result "[INFO] journalctl not found"
    fi
    echo ""

    #----------------------------------------
    # 3. Audit daemon (auditd)
    #----------------------------------------
    echo -e "${BLUE}[*] Audit daemon (auditd):${NC}"
    log_result "--- Audit Daemon ---"

    if command -v auditctl &>/dev/null; then
        echo -e "    auditd найден"
        log_result "auditd: found"

        if systemctl is-active --quiet auditd 2>/dev/null; then
            echo -e "${GREEN}    [✓] auditd запущен${NC}"
            log_result "[OK] auditd is running"

            # Правила аудита
            AUDIT_RULES=$(auditctl -l 2>/dev/null)
            AUDIT_RULE_COUNT=$(echo "$AUDIT_RULES" | grep -c -v "^No rules")

            if [[ $AUDIT_RULE_COUNT -gt 0 ]]; then
                echo -e "    Правил аудита: $AUDIT_RULE_COUNT"
                log_result "Audit rules: $AUDIT_RULE_COUNT"

                echo ""
                echo -e "${BLUE}    Текущие правила:${NC}"
                echo "$AUDIT_RULES" | head -20 | while read -r line; do
                    echo -e "    $line"
                    log_result "Rule: $line"
                done

                if [[ $AUDIT_RULE_COUNT -gt 20 ]]; then
                    echo -e "${YELLOW}    ... показано 20 из $AUDIT_RULE_COUNT${NC}"
                fi
            else
                echo -e "${YELLOW}    [!] Правила аудита не настроены${NC}"
                echo -e "${YELLOW}        Рекомендация: настроить правила аудита${NC}"
                log_result "[WARNING] No audit rules configured"
            fi

            # Конфиг auditd
            if [[ -f /etc/audit/auditd.conf ]]; then
                echo ""
                echo -e "${BLUE}    Настройки auditd:${NC}"

                MAX_LOG=$(grep "^max_log_file " /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
                MAX_LOG=${MAX_LOG:-"unknown"}
                echo -e "    max_log_file: ${MAX_LOG}MB"
                log_result "max_log_file: ${MAX_LOG}MB"

                MAX_ACTION=$(grep "^max_log_file_action" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
                MAX_ACTION=${MAX_ACTION:-"unknown"}
                echo -e "    max_log_file_action: $MAX_ACTION"
                log_result "max_log_file_action: $MAX_ACTION"

                SPACE_LEFT_ACTION=$(grep "^space_left_action" /etc/audit/auditd.conf 2>/dev/null | awk '{print $3}')
                SPACE_LEFT_ACTION=${SPACE_LEFT_ACTION:-"unknown"}
                echo -e "    space_left_action: $SPACE_LEFT_ACTION"
                log_result "space_left_action: $SPACE_LEFT_ACTION"
            fi

        else
            echo -e "${YELLOW}    [!] auditd НЕ запущен${NC}"
            echo -e "${YELLOW}        Рекомендация: systemctl enable --now auditd${NC}"
            log_result "[WARNING] auditd is not running"
        fi

        if systemctl is-enabled --quiet auditd 2>/dev/null; then
            echo -e "${GREEN}    [✓] auditd в автозапуске${NC}"
            log_result "[OK] auditd is enabled"
        else
            echo -e "${YELLOW}    [!] auditd НЕ в автозапуске${NC}"
            log_result "[WARNING] auditd is not enabled"
        fi
    else
        echo -e "${RED}    [!] auditd не установлен!${NC}"
        echo -e "${YELLOW}        Рекомендация: apt install auditd${NC}"
        log_result "[WARNING] auditd is not installed"
    fi
    echo ""

    #----------------------------------------
    # 4. Важные лог-файлы
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка важных лог-файлов:${NC}"
    log_result "--- Important Log Files ---"

    declare -A LOG_FILES
    LOG_FILES=(
        ["/var/log/syslog"]="Системный лог"
        ["/var/log/auth.log"]="Аутентификация"
        ["/var/log/kern.log"]="Ядро"
        ["/var/log/messages"]="Общие сообщения"
        ["/var/log/secure"]="Безопасность (RHEL)"
        ["/var/log/boot.log"]="Загрузка"
        ["/var/log/dmesg"]="Загрузка ядра"
        ["/var/log/dpkg.log"]="Установка пакетов"
        ["/var/log/apt/history.log"]="Apt история"
        ["/var/log/cron.log"]="Cron задачи"
        ["/var/log/faillog"]="Неудачные входы"
        ["/var/log/lastlog"]="Последние входы"
        ["/var/log/wtmp"]="История входов"
        ["/var/log/btmp"]="Неудачные входы"
        ["/var/log/audit/audit.log"]="Аудит"
    )

    for logfile in "${!LOG_FILES[@]}"; do
        DESCRIPTION="${LOG_FILES[$logfile]}"

        if [[ -f "$logfile" ]]; then
            SIZE=$(du -sh "$logfile" 2>/dev/null | awk '{print $1}')
            PERMS=$(stat -c "%a" "$logfile" 2>/dev/null)
            OWNER=$(stat -c "%U:%G" "$logfile" 2>/dev/null)
            MODIFIED=$(stat -c "%y" "$logfile" 2>/dev/null | cut -d'.' -f1)

            echo -e "${GREEN}    [✓] $logfile${NC}"
            echo -e "        $DESCRIPTION | $SIZE | $PERMS | $OWNER | $MODIFIED"
            log_result "[OK] $logfile: $SIZE, $PERMS, $OWNER, $MODIFIED"

            # Проверка прав
            if [[ "$PERMS" -gt 640 ]]; then
                echo -e "${YELLOW}        [!] Права слишком открытые: $PERMS (рекомендуется 640)${NC}"
                log_result "[WARNING] $logfile permissions too open: $PERMS"
            fi
        else
            echo -e "${YELLOW}    [—] $logfile — не найден ($DESCRIPTION)${NC}"
            log_result "[INFO] $logfile: not found ($DESCRIPTION)"
        fi
    done
    echo ""

    #----------------------------------------
    # 5. Ротация логов
    #----------------------------------------
    echo -e "${BLUE}[*] Ротация логов (logrotate):${NC}"
    log_result "--- Log Rotation ---"

    if command -v logrotate &>/dev/null; then
        echo -e "${GREEN}    [✓] logrotate установлен${NC}"
        log_result "[OK] logrotate is installed"

        # Основной конфиг
        if [[ -f /etc/logrotate.conf ]]; then
            echo -e "${BLUE}    Основные настройки:${NC}"

            ROTATE_PERIOD=$(grep -E "^(daily|weekly|monthly|yearly)" /etc/logrotate.conf 2>/dev/null | head -1)
            ROTATE_PERIOD=${ROTATE_PERIOD:-"not set"}
            echo -e "    Период: $ROTATE_PERIOD"
            log_result "Rotation period: $ROTATE_PERIOD"

            ROTATE_COUNT=$(grep "^rotate" /etc/logrotate.conf 2>/dev/null | awk '{print $2}' | head -1)
            ROTATE_COUNT=${ROTATE_COUNT:-"not set"}
            echo -e "    Хранить: $ROTATE_COUNT ротаций"
            log_result "Rotation count: $ROTATE_COUNT"

            COMPRESS_OPT=$(grep "^compress" /etc/logrotate.conf 2>/dev/null)
            if [[ -n "$COMPRESS_OPT" ]]; then
                echo -e "${GREEN}    [✓] Сжатие включено${NC}"
                log_result "[OK] Compression enabled"
            else
                echo -e "${YELLOW}    [!] Сжатие не включено${NC}"
                log_result "[WARNING] Compression not enabled"
            fi
        fi

        # Количество конфигов
        LOGROTATE_D_COUNT=$(ls /etc/logrotate.d/ 2>/dev/null | wc -l)
        echo -e "    Конфигов в /etc/logrotate.d/: $LOGROTATE_D_COUNT"
        log_result "Logrotate configs: $LOGROTATE_D_COUNT"

        # Последний запуск
        if [[ -f /var/lib/logrotate/status ]]; then
            LAST_ROTATE=$(head -1 /var/lib/logrotate/status 2>/dev/null)
            echo -e "    Последний запуск: $LAST_ROTATE"
            log_result "Last rotation: $LAST_ROTATE"
        fi
    else
        echo -e "${RED}    [!] logrotate не установлен!${NC}"
        echo -e "${YELLOW}        Рекомендация: apt install logrotate${NC}"
        log_result "[WARNING] logrotate is not installed"
    fi
    echo ""

    #----------------------------------------
    # 6. Удалённое логирование
    #----------------------------------------
    echo -e "${BLUE}[*] Удалённое логирование:${NC}"
    log_result "--- Remote Logging ---"

    REMOTE_LOG=0

    # Проверяем rsyslog
    if [[ -f /etc/rsyslog.conf ]]; then
        REMOTE_RSYSLOG=$(grep -E "^(\*\.\*|@@)" /etc/rsyslog.conf 2>/dev/null | grep -v "^#")
        if [[ -n "$REMOTE_RSYSLOG" ]]; then
            echo -e "${GREEN}    [✓] Удалённое логирование настроено (rsyslog)${NC}"
            echo "$REMOTE_RSYSLOG" | while read -r line; do
                echo -e "    → $line"
                log_result "Remote log: $line"
            done
            REMOTE_LOG=1
        fi

        # Проверяем в rsyslog.d
        REMOTE_D=$(grep -rE "^(\*\.\*|@@)" /etc/rsyslog.d/ 2>/dev/null | grep -v "^#")
        if [[ -n "$REMOTE_D" ]]; then
            echo -e "${GREEN}    [✓] Удалённое логирование (rsyslog.d)${NC}"
            echo "$REMOTE_D" | while read -r line; do
                echo -e "    → $line"
                log_result "Remote log: $line"
            done
            REMOTE_LOG=1
        fi
    fi

    if [[ $REMOTE_LOG -eq 0 ]]; then
        echo -e "${YELLOW}    [!] Удалённое логирование не настроено${NC}"
        echo -e "${YELLOW}        Рекомендация: настроить отправку логов на удалённый сервер${NC}"
        log_result "[WARNING] Remote logging is not configured"
    fi
    echo ""

    #----------------------------------------
    # 7. Последние события безопасности
    #----------------------------------------
    echo -e "${BLUE}[*] Последние события безопасности:${NC}"
    log_result "--- Recent Security Events ---"

    # Неудачные входы
    if [[ -f /var/log/auth.log ]]; then
        echo -e "${BLUE}    Неудачные попытки входа (последние 24ч):${NC}"
        FAILED_24H=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date +%b\ %d)" | wc -l)
        echo -e "    Количество: $FAILED_24H"
        log_result "Failed logins (24h): $FAILED_24H"

        if [[ $FAILED_24H -gt 20 ]]; then
            echo -e "${RED}    [!] Много неудачных попыток! Возможен брутфорс!${NC}"
            log_result "[CRITICAL] Possible brute force: $FAILED_24H attempts"

            echo -e "${BLUE}    Топ IP по неудачным входам:${NC}"
            grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -5 | while read -r count ip; do
                echo -e "${RED}    → $ip: $count попыток${NC}"
                log_result "Brute force IP: $ip ($count attempts)"
            done
        fi
        echo ""

        # Успешные входы
        echo -e "${BLUE}    Успешные входы (последние 24ч):${NC}"
        SUCCESS_24H=$(grep "Accepted" /var/log/auth.log 2>/dev/null | grep "$(date +%b\ %d)" | wc -l)
        echo -e "    Количество: $SUCCESS_24H"
        log_result "Successful logins (24h): $SUCCESS_24H"

        grep "Accepted" /var/log/auth.log 2>/dev/null | tail -5 | while read -r line; do
            echo -e "    → $line"
            log_result "Login: $line"
        done
        echo ""

        # Sudo использование
        echo -e "${BLUE}    Использование sudo (последние 24ч):${NC}"
        SUDO_24H=$(grep "sudo:" /var/log/auth.log 2>/dev/null | grep "$(date +%b\ %d)" | grep "COMMAND" | wc -l)
        echo -e "    Количество: $SUDO_24H"
        log_result "Sudo commands (24h): $SUDO_24H"

        grep "sudo:" /var/log/auth.log 2>/dev/null | grep "COMMAND" | tail -5 | while read -r line; do
            echo -e "    → $line"
            log_result "Sudo: $line"
        done

    elif [[ -f /var/log/secure ]]; then
        echo -e "${BLUE}    Неудачные попытки входа (из /var/log/secure):${NC}"
        FAILED=$(grep "Failed password" /var/log/secure 2>/dev/null | wc -l)
        echo -e "    Всего: $FAILED"
        log_result "Failed logins: $FAILED"
    else
        echo -e "${YELLOW}    [!] Лог аутентификации не найден${NC}"
        log_result "[WARNING] Auth log not found"
    fi
    echo ""

    #----------------------------------------
    # 8. Целостность логов
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка целостности логов:${NC}"
    log_result "--- Log Integrity Check ---"

    # Проверяем пустые логи
    EMPTY_LOGS=0
    for logfile in /var/log/syslog /var/log/auth.log /var/log/kern.log; do
        if [[ -f "$logfile" && ! -s "$logfile" ]]; then
            echo -e "${RED}    [!] $logfile ПУСТОЙ — возможна очистка логов!${NC}"
            log_result "[CRITICAL] Empty log file: $logfile"
            EMPTY_LOGS=1
        fi
    done

    if [[ $EMPTY_LOGS -eq 0 ]]; then
        echo -e "${GREEN}    [✓] Лог-файлы не пустые${NC}"
        log_result "[OK] Log files are not empty"
    fi

    # Проверяем разрывы во времени
    if [[ -f /var/log/syslog ]]; then
        FIRST_ENTRY=$(head -1 /var/log/syslog 2>/dev/null | awk '{print $1, $2, $3}')
        LAST_ENTRY=$(tail -1 /var/log/syslog 2>/dev/null | awk '{print $1, $2, $3}')
        echo -e "    Syslog: $FIRST_ENTRY → $LAST_ENTRY"
        log_result "Syslog range: $FIRST_ENTRY to $LAST_ENTRY"
    fi
    echo ""

    #----------------------------------------
    # 9. Рекомендации по аудиту
    #----------------------------------------
    echo -e "${BLUE}[*] Рекомендуемые правила аудита:${NC}"
    log_result "--- Recommended Audit Rules ---"

    echo -e "${CYAN}"
    cat << 'EOF'
    # Мониторинг изменений учётных записей
    -w /etc/passwd -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/group -p wa -k identity
    -w /etc/gshadow -p wa -k identity
    -w /etc/sudoers -p wa -k sudoers

    # Мониторинг входов
    -w /var/log/faillog -p wa -k logins
    -w /var/log/lastlog -p wa -k logins
    -w /var/log/wtmp -p wa -k logins
    -w /var/log/btmp -p wa -k logins

    # Мониторинг сетевой конфигурации
    -w /etc/hosts -p wa -k network
    -w /etc/network/ -p wa -k network

    # Мониторинг cron
    -w /etc/crontab -p wa -k cron
    -w /etc/cron.d/ -p wa -k cron

    # Мониторинг SSH
    -w /etc/ssh/sshd_config -p wa -k sshd
EOF
    echo -e "${NC}"

    log_result "See recommended audit rules above"
    echo ""

    echo -e "${GREEN}[✓] Аудит логирования завершён${NC}"
}

# Запуск
logging_audit
