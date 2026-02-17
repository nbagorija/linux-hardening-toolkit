#!/bin/bash

#============================================
# Module: System Information Gathering
# Description: Collects basic system info
#              for security assessment
#============================================

system_info_audit() {
    echo -e "${CYAN}[MODULE] Сбор информации о системе${NC}"
    echo ""

    # Имя хоста
    echo -e "${BLUE}[*] Имя хоста:${NC}"
    log_result "Hostname: $(hostname)"
    echo ""

    # Информация об ОС
    echo -e "${BLUE}[*] Операционная система:${NC}"
    if [[ -f /etc/os-release ]]; then
        OS_NAME=$(grep "^PRETTY_NAME" /etc/os-release | cut -d'"' -f2)
        log_result "OS: $OS_NAME"
    else
        log_result "OS: $(uname -o)"
    fi
    echo ""

    # Версия ядра
    echo -e "${BLUE}[*] Ядро:${NC}"
    KERNEL=$(uname -r)
    log_result "Kernel: $KERNEL"

    # Проверка устаревшего ядра
    KERNEL_MAJOR=$(echo "$KERNEL" | cut -d'.' -f1)
    KERNEL_MINOR=$(echo "$KERNEL" | cut -d'.' -f2)
    if [[ $KERNEL_MAJOR -lt 5 ]]; then
        echo -e "${RED}[!] ВНИМАНИЕ: Ядро устаревшее! Рекомендуется обновление${NC}"
        log_result "[WARNING] Outdated kernel detected"
    else
        echo -e "${GREEN}[✓] Версия ядра актуальна${NC}"
        log_result "[OK] Kernel version is current"
    fi
    echo ""

    # Архитектура
    echo -e "${BLUE}[*] Архитектура:${NC}"
    log_result "Architecture: $(uname -m)"
    echo ""

    # Время работы системы
    echo -e "${BLUE}[*] Uptime:${NC}"
    log_result "Uptime: $(uptime -p)"
    echo ""

    # Последняя перезагрузка
    echo -e "${BLUE}[*] Последняя перезагрузка:${NC}"
    log_result "Last reboot: $(who -b | awk '{print $3, $4}')"
    echo ""

    # Информация о CPU
    echo -e "${BLUE}[*] Процессор:${NC}"
    CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)
    CPU_CORES=$(grep -c "^processor" /proc/cpuinfo)
    log_result "CPU: $CPU_MODEL"
    log_result "CPU Cores: $CPU_CORES"
    echo ""

    # Оперативная память
    echo -e "${BLUE}[*] Оперативная память:${NC}"
    TOTAL_RAM=$(free -h | awk '/^Mem:/{print $2}')
    USED_RAM=$(free -h | awk '/^Mem:/{print $3}')
    AVAILABLE_RAM=$(free -h | awk '/^Mem:/{print $7}')
    log_result "Total RAM: $TOTAL_RAM"
    log_result "Used RAM: $USED_RAM"
    log_result "Available RAM: $AVAILABLE_RAM"

    # Проверка свопа
    SWAP_TOTAL=$(free -h | awk '/^Swap:/{print $2}')
    if [[ "$SWAP_TOTAL" == "0B" || "$SWAP_TOTAL" == "0" ]]; then
        echo -e "${YELLOW}[!] Swap не настроен${NC}"
        log_result "[INFO] Swap is not configured"
    else
        log_result "Swap: $SWAP_TOTAL"
    fi
    echo ""

    # Дисковое пространство
    echo -e "${BLUE}[*] Дисковое пространство:${NC}"
    log_result "--- Disk Usage ---"
    df -h --output=target,size,used,avail,pcent -x tmpfs -x devtmpfs | tee -a "$REPORT_FILE"
    echo ""

    # Проверка заполненности дисков
    DISK_USAGE=$(df -h --output=pcent -x tmpfs -x devtmpfs | tail -n +2 | tr -d ' %')
    for usage in $DISK_USAGE; do
        if [[ $usage -gt 90 ]]; then
            echo -e "${RED}[!] ВНИМАНИЕ: Диск заполнен более чем на 90%!${NC}"
            log_result "[CRITICAL] Disk usage above 90%"
        elif [[ $usage -gt 75 ]]; then
            echo -e "${YELLOW}[!] Диск заполнен более чем на 75%${NC}"
            log_result "[WARNING] Disk usage above 75%"
        fi
    done
    echo ""

    # Часовой пояс и NTP
    echo -e "${BLUE}[*] Часовой пояс:${NC}"
    TIMEZONE=$(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3}')
    if [[ -n "$TIMEZONE" ]]; then
        log_result "Timezone: $TIMEZONE"
    else
        log_result "Timezone: $(cat /etc/timezone 2>/dev/null || echo 'Unknown')"
    fi

    # Проверка NTP синхронизации
    NTP_STATUS=$(timedatectl 2>/dev/null | grep "NTP" | head -1)
    if echo "$NTP_STATUS" | grep -qi "yes\|active"; then
        echo -e "${GREEN}[✓] NTP синхронизация активна${NC}"
        log_result "[OK] NTP synchronization is active"
    else
        echo -e "${YELLOW}[!] NTP синхронизация не настроена${NC}"
        log_result "[WARNING] NTP synchronization is not active"
    fi
    echo ""

    # Текущие пользователи в системе
    echo -e "${BLUE}[*] Текущие пользователи в системе:${NC}"
    LOGGED_USERS=$(who | wc -l)
    log_result "Logged in users: $LOGGED_USERS"
    who | tee -a "$REPORT_FILE"
    echo ""

    # Количество установленных пакетов
    echo -e "${BLUE}[*] Установленные пакеты:${NC}"
    if command -v dpkg &>/dev/null; then
        PKG_COUNT=$(dpkg -l | grep "^ii" | wc -l)
        log_result "Installed packages (dpkg): $PKG_COUNT"
    elif command -v rpm &>/dev/null; then
        PKG_COUNT=$(rpm -qa | wc -l)
        log_result "Installed packages (rpm): $PKG_COUNT"
    fi
    echo ""

    # Проверка обновлений безопасности
    echo -e "${BLUE}[*] Проверка обновлений безопасности:${NC}"
    if command -v apt &>/dev/null; then
        apt list --upgradable 2>/dev/null | grep -i "security" | head -5
        UPDATES=$(apt list --upgradable 2>/dev/null | wc -l)
        if [[ $UPDATES -gt 1 ]]; then
            echo -e "${YELLOW}[!] Доступно обновлений: $((UPDATES - 1))${NC}"
            log_result "[WARNING] $((UPDATES - 1)) updates available"
        else
            echo -e "${GREEN}[✓] Система обновлена${NC}"
            log_result "[OK] System is up to date"
        fi
    fi
    echo ""

    echo -e "${GREEN}[✓] Сбор информации о системе завершён${NC}"
}

# Запуск
system_info_audit
