#!/bin/bash

#============================================
# Module: Network Audit
# Description: Audits network configuration,
#              connections, and kernel params
#============================================

network_audit() {
    echo -e "${CYAN}[MODULE] Сетевой аудит${NC}"
    echo ""

    #----------------------------------------
    # 1. Сетевые интерфейсы
    #----------------------------------------
    echo -e "${BLUE}[*] Сетевые интерфейсы:${NC}"
    log_result "--- Network Interfaces ---"

    if command -v ip &>/dev/null; then
        ip -br addr 2>/dev/null | while read -r iface state addr; do
            if [[ "$state" == "UP" ]]; then
                echo -e "${GREEN}    [UP]   $iface — $addr${NC}"
            elif [[ "$state" == "DOWN" ]]; then
                echo -e "${RED}    [DOWN] $iface — $addr${NC}"
            else
                echo -e "${YELLOW}    [$state] $iface — $addr${NC}"
            fi
            log_result "Interface: $iface ($state) $addr"
        done
    else
        ifconfig 2>/dev/null | tee -a "$REPORT_FILE"
    fi
    echo ""

    #----------------------------------------
    # 2. Promiscuous mode
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка Promiscuous Mode:${NC}"
    log_result "--- Promiscuous Mode Check ---"

    PROMISC_FOUND=0
    for iface in $(ip -br link 2>/dev/null | awk '{print $1}'); do
        FLAGS=$(ip link show "$iface" 2>/dev/null | head -1)
        if echo "$FLAGS" | grep -qi "PROMISC"; then
            echo -e "${RED}    [!] $iface в режиме PROMISC — возможен сниффинг!${NC}"
            log_result "[CRITICAL] $iface is in promiscuous mode"
            PROMISC_FOUND=1
        fi
    done

    if [[ $PROMISC_FOUND -eq 0 ]]; then
        echo -e "${GREEN}    [✓] Ни один интерфейс не в режиме PROMISC${NC}"
        log_result "[OK] No interfaces in promiscuous mode"
    fi
    echo ""

    #----------------------------------------
    # 3. IP адреса
    #----------------------------------------
    echo -e "${BLUE}[*] IP адреса:${NC}"
    log_result "--- IP Addresses ---"

    # Внутренний IP
    INTERNAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo -e "    Внутренний IP: $INTERNAL_IP"
    log_result "Internal IP: $INTERNAL_IP"

    # Внешний IP
    echo -e "${YELLOW}    Получение внешнего IP...${NC}"
    EXTERNAL_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null)
    if [[ -n "$EXTERNAL_IP" ]]; then
        echo -e "    Внешний IP:    $EXTERNAL_IP"
        log_result "External IP: $EXTERNAL_IP"
    else
        echo -e "${YELLOW}    [!] Не удалось получить внешний IP${NC}"
        log_result "[INFO] Could not retrieve external IP"
    fi
    echo ""

    #----------------------------------------
    # 4. Таблица маршрутизации
    #----------------------------------------
    echo -e "${BLUE}[*] Таблица маршрутизации:${NC}"
    log_result "--- Routing Table ---"

    if command -v ip &>/dev/null; then
        ip route 2>/dev/null | while read -r line; do
            echo -e "    $line"
            log_result "$line"
        done
    else
        route -n 2>/dev/null | tee -a "$REPORT_FILE"
    fi

    # Шлюз по умолчанию
    DEFAULT_GW=$(ip route 2>/dev/null | grep default | awk '{print $3}')
    echo ""
    echo -e "    Шлюз по умолчанию: $DEFAULT_GW"
    log_result "Default gateway: $DEFAULT_GW"
    echo ""

    #----------------------------------------
    # 5. DNS настройки
    #----------------------------------------
    echo -e "${BLUE}[*] DNS настройки:${NC}"
    log_result "--- DNS Configuration ---"

    if [[ -f /etc/resolv.conf ]]; then
        echo -e "    /etc/resolv.conf:"
        grep -v "^#" /etc/resolv.conf | grep -v "^$" | while read -r line; do
            echo -e "    $line"
            log_result "$line"
        done

        # Проверяем DNS серверы
        DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}')
        DNS_COUNT=$(echo "$DNS_SERVERS" | wc -l)

        echo ""
        echo -e "    DNS серверов: $DNS_COUNT"
        log_result "DNS servers count: $DNS_COUNT"

        # Предупреждение о публичных DNS
        echo "$DNS_SERVERS" | while read -r dns; do
            case "$dns" in
                "8.8.8.8"|"8.8.4.4")
                    echo -e "${YELLOW}    [!] Используется Google DNS: $dns${NC}"
                    log_result "[INFO] Google DNS: $dns"
                    ;;
                "1.1.1.1"|"1.0.0.1")
                    echo -e "${YELLOW}    [!] Используется Cloudflare DNS: $dns${NC}"
                    log_result "[INFO] Cloudflare DNS: $dns"
                    ;;
                "208.67.222.222"|"208.67.220.220")
                    echo -e "${YELLOW}    [!] Используется OpenDNS: $dns${NC}"
                    log_result "[INFO] OpenDNS: $dns"
                    ;;
            esac
        done
    else
        echo -e "${YELLOW}    [!] /etc/resolv.conf не найден${NC}"
        log_result "[WARNING] /etc/resolv.conf not found"
    fi
    echo ""

    #----------------------------------------
    # 6. Активные соединения
    #----------------------------------------
    echo -e "${BLUE}[*] Активные соединения:${NC}"
    log_result "--- Active Connections ---"

    # ESTABLISHED соединения
    echo -e "${BLUE}    Установленные (ESTABLISHED):${NC}"
    ESTABLISHED=$(ss -tnp state established 2>/dev/null)
    EST_COUNT=$(echo "$ESTABLISHED" | tail -n +2 | wc -l)

    if [[ $EST_COUNT -gt 0 ]]; then
        echo "$ESTABLISHED" | head -15 | while read -r line; do
            echo -e "    $line"
            log_result "$line"
        done

        if [[ $EST_COUNT -gt 15 ]]; then
            echo -e "${YELLOW}    ... показано 15 из $EST_COUNT${NC}"
        fi

        echo ""
        echo -e "    Всего ESTABLISHED: $EST_COUNT"
        log_result "Total ESTABLISHED: $EST_COUNT"

        if [[ $EST_COUNT -gt 50 ]]; then
            echo -e "${YELLOW}    [!] Много активных соединений: $EST_COUNT${NC}"
            log_result "[WARNING] Many active connections: $EST_COUNT"
        fi
    else
        echo -e "${GREEN}    [✓] Нет установленных соединений${NC}"
        log_result "[OK] No established connections"
    fi
    echo ""

    # LISTENING порты
    echo -e "${BLUE}    Слушающие порты (LISTEN):${NC}"
    log_result "--- Listening Ports ---"

    ss -tlnp 2>/dev/null | while read -r line; do
        echo -e "    $line"
        log_result "$line"
    done
    echo ""

    #----------------------------------------
    # 7. Подозрительные соединения
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка подозрительных соединений:${NC}"
    log_result "--- Suspicious Connections Check ---"

    SUSPICIOUS=0

    # Соединения на нестандартных портах
    UNUSUAL_PORTS=$(ss -tnp state established 2>/dev/null | awk '{print $4}' | grep -oP ':\K[0-9]+$' | sort -u)

    SUSPICIOUS_PORTS=(4444 5555 6666 6667 1337 31337 12345 54321 9999 8888)

    for port in $UNUSUAL_PORTS; do
        for sus_port in "${SUSPICIOUS_PORTS[@]}"; do
            if [[ "$port" == "$sus_port" ]]; then
                echo -e "${RED}    [!] Подозрительный порт обнаружен: $port${NC}"
                log_result "[CRITICAL] Suspicious port detected: $port"
                SUSPICIOUS=1

                # Показываем соединение
                ss -tnp state established 2>/dev/null | grep ":$port" | while read -r line; do
                    echo -e "${RED}        $line${NC}"
                    log_result "Suspicious connection: $line"
                done
            fi
        done
    done

    if [[ $SUSPICIOUS -eq 0 ]]; then
        echo -e "${GREEN}    [✓] Подозрительных соединений не обнаружено${NC}"
        log_result "[OK] No suspicious connections detected"
    fi
    echo ""

    #----------------------------------------
    # 8. ARP таблица
    #----------------------------------------
    echo -e "${BLUE}[*] ARP таблица:${NC}"
    log_result "--- ARP Table ---"

    if command -v ip &>/dev/null; then
        ARP_ENTRIES=$(ip neigh 2>/dev/null)
        ARP_COUNT=$(echo "$ARP_ENTRIES" | grep -c .)

        echo "$ARP_ENTRIES" | while read -r line; do
            echo -e "    $line"
            log_result "$line"
        done

        echo ""
        echo -e "    Записей в ARP таблице: $ARP_COUNT"
        log_result "ARP entries: $ARP_COUNT"

        # Проверка дубликатов MAC
        DUPLICATE_MAC=$(ip neigh 2>/dev/null | awk '{print $5}' | sort | uniq -d)
        if [[ -n "$DUPLICATE_MAC" ]]; then
            echo -e "${RED}    [!] Обнаружены дублирующиеся MAC адреса!${NC}"
            echo -e "${RED}        Возможна ARP spoofing атака!${NC}"
            echo -e "${RED}        MAC: $DUPLICATE_MAC${NC}"
            log_result "[CRITICAL] Duplicate MAC addresses detected: $DUPLICATE_MAC"
        else
            echo -e "${GREEN}    [✓] Дублирующихся MAC адресов не найдено${NC}"
            log_result "[OK] No duplicate MAC addresses"
        fi
    fi
    echo ""

    #----------------------------------------
    # 9. Сетевые параметры ядра
    #----------------------------------------
    echo -e "${BLUE}[*] Сетевые параметры ядра:${NC}"
    log_result "--- Kernel Network Parameters ---"

    declare -A KERNEL_PARAMS
    KERNEL_PARAMS=(
        ["net.ipv4.ip_forward"]="0|IP forwarding"
        ["net.ipv4.conf.all.accept_source_route"]="0|Source routing"
        ["net.ipv4.conf.all.accept_redirects"]="0|ICMP redirects"
        ["net.ipv4.conf.all.secure_redirects"]="1|Secure redirects"
        ["net.ipv4.conf.all.log_martians"]="1|Log martians"
        ["net.ipv4.conf.all.rp_filter"]="1|Reverse path filter"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1|Ignore broadcast pings"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1|Ignore bogus ICMP"
        ["net.ipv4.tcp_syncookies"]="1|SYN cookies"
        ["net.ipv6.conf.all.accept_redirects"]="0|IPv6 redirects"
        ["net.ipv6.conf.all.accept_source_route"]="0|IPv6 source routing"
    )

    for param in "${!KERNEL_PARAMS[@]}"; do
        IFS='|' read -r expected description <<< "${KERNEL_PARAMS[$param]}"
        actual=$(sysctl -n "$param" 2>/dev/null)

        if [[ -z "$actual" ]]; then
            echo -e "${YELLOW}    [—] $description: параметр не найден${NC}"
            log_result "[INFO] $param: not found"
            continue
        fi

        if [[ "$actual" == "$expected" ]]; then
            echo -e "${GREEN}    [✓] $description ($param = $actual)${NC}"
            log_result "[OK] $param = $actual"
        else
            echo -e "${RED}    [!] $description ($param = $actual, рекомендуется $expected)${NC}"
            log_result "[WARNING] $param = $actual (recommended: $expected)"
        fi
    done
    echo ""

    #----------------------------------------
    # 10. Hosts файл
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка /etc/hosts:${NC}"
    log_result "--- Hosts File ---"

    if [[ -f /etc/hosts ]]; then
        HOSTS_ENTRIES=$(grep -v "^#" /etc/hosts | grep -v "^$" | wc -l)
        echo -e "    Записей в /etc/hosts: $HOSTS_ENTRIES"
        log_result "Hosts entries: $HOSTS_ENTRIES"

        if [[ $HOSTS_ENTRIES -gt 10 ]]; then
            echo -e "${YELLOW}    [!] Много записей — проверьте на подозрительные${NC}"
            log_result "[WARNING] Many hosts entries"
        fi

        # Показываем нестандартные записи
        grep -v "^#" /etc/hosts | grep -v "^$" | grep -v "localhost" | grep -v "^::1" | while read -r line; do
            echo -e "${YELLOW}    → $line${NC}"
            log_result "Custom host: $line"
        done
    fi
    echo ""

    #----------------------------------------
    # 11. Сетевые сокеты (UNIX)
    #----------------------------------------
    echo -e "${BLUE}[*] UNIX сокеты (слушающие):${NC}"
    log_result "--- UNIX Sockets ---"

    UNIX_SOCKETS=$(ss -xlnp 2>/dev/null | wc -l)
    echo -e "    Слушающих UNIX сокетов: $UNIX_SOCKETS"
    log_result "Listening UNIX sockets: $UNIX_SOCKETS"
    echo ""

    #----------------------------------------
    # 12. Проверка WiFi
    #----------------------------------------
    echo -e "${BLUE}[*] Беспроводные интерфейсы:${NC}"
    log_result "--- Wireless Interfaces ---"

    if command -v iwconfig &>/dev/null; then
        WIFI=$(iwconfig 2>/dev/null | grep -v "no wireless")
        if [[ -n "$WIFI" ]]; then
            echo "$WIFI" | while read -r line; do
                echo -e "    $line"
                log_result "$line"
            done
        else
            echo -e "    Беспроводных интерфейсов не найдено"
            log_result "No wireless interfaces"
        fi
    elif command -v iw &>/dev/null; then
        iw dev 2>/dev/null | while read -r line; do
            echo -e "    $line"
            log_result "$line"
        done
    else
        echo -e "    Утилиты для проверки WiFi не найдены"
        log_result "No wireless tools found"
    fi
    echo ""

    echo -e "${GREEN}[✓] Сетевой аудит завершён${NC}"
}

# Запуск
network_audit
