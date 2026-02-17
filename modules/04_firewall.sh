#!/bin/bash

#============================================
# Module: Firewall Audit
# Description: Analyzes firewall configuration
#              (iptables, nftables, ufw)
#============================================

firewall_audit() {
    echo -e "${CYAN}[MODULE] Аудит файрвола${NC}"
    echo ""

    #----------------------------------------
    # 1. Определяем какой файрвол используется
    #----------------------------------------
    echo -e "${BLUE}[*] Определение файрвола:${NC}"
    log_result "--- Firewall Detection ---"

    HAS_UFW=0
    HAS_IPTABLES=0
    HAS_NFTABLES=0
    HAS_FIREWALLD=0

    if command -v ufw &>/dev/null; then
        HAS_UFW=1
        echo -e "    [✓] UFW найден"
        log_result "UFW: found"
    fi

    if command -v iptables &>/dev/null; then
        HAS_IPTABLES=1
        echo -e "    [✓] iptables найден"
        log_result "iptables: found"
    fi

    if command -v nft &>/dev/null; then
        HAS_NFTABLES=1
        echo -e "    [✓] nftables найден"
        log_result "nftables: found"
    fi

    if command -v firewall-cmd &>/dev/null; then
        HAS_FIREWALLD=1
        echo -e "    [✓] firewalld найден"
        log_result "firewalld: found"
    fi

    if [[ $HAS_UFW -eq 0 && $HAS_IPTABLES -eq 0 && $HAS_NFTABLES -eq 0 && $HAS_FIREWALLD -eq 0 ]]; then
        echo -e "${RED}[!] ВНИМАНИЕ: Файрвол не обнаружен!${NC}"
        log_result "[CRITICAL] No firewall detected"
        echo -e "${YELLOW}    Рекомендация: установить ufw или настроить iptables${NC}"
        return
    fi
    echo ""

    #----------------------------------------
    # 2. UFW
    #----------------------------------------
    if [[ $HAS_UFW -eq 1 ]]; then
        echo -e "${BLUE}[*] Статус UFW:${NC}"
        log_result "--- UFW Status ---"

        UFW_STATUS=$(ufw status 2>/dev/null)

        if echo "$UFW_STATUS" | grep -q "active"; then
            echo -e "${GREEN}[✓] UFW активен${NC}"
            log_result "[OK] UFW is active"

            echo ""
            echo -e "${BLUE}[*] Правила UFW:${NC}"
            log_result "--- UFW Rules ---"
            ufw status verbose 2>/dev/null | tee -a "$REPORT_FILE"

            # Считаем правила
            UFW_RULES=$(ufw status numbered 2>/dev/null | grep -c "^\[")
            echo ""
            echo -e "    Всего правил: $UFW_RULES"
            log_result "Total UFW rules: $UFW_RULES"

            # Политики по умолчанию
            echo ""
            echo -e "${BLUE}[*] Политики UFW по умолчанию:${NC}"
            log_result "--- UFW Default Policies ---"

            UFW_INCOMING=$(ufw status verbose 2>/dev/null | grep "Default:" | head -1)
            echo -e "    $UFW_INCOMING"
            log_result "$UFW_INCOMING"

            if echo "$UFW_INCOMING" | grep -q "allow"; then
                echo -e "${RED}[!] ВНИМАНИЕ: Входящий трафик разрешён по умолчанию!${NC}"
                echo -e "${RED}    Рекомендация: ufw default deny incoming${NC}"
                log_result "[CRITICAL] Default incoming policy is allow"
            fi

        else
            echo -e "${RED}[!] UFW неактивен!${NC}"
            log_result "[WARNING] UFW is inactive"
            echo -e "${YELLOW}    Рекомендация: sudo ufw enable${NC}"
        fi
        echo ""
    fi

    #----------------------------------------
    # 3. iptables
    #----------------------------------------
    if [[ $HAS_IPTABLES -eq 1 ]]; then
        echo -e "${BLUE}[*] Правила iptables:${NC}"
        log_result "--- iptables Rules ---"

        # Политики по умолчанию
        echo -e "${BLUE}[*] Политики по умолчанию (iptables):${NC}"
        log_result "--- iptables Default Policies ---"

        INPUT_POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1 | awk '{print $4}' | tr -d ')')
        FORWARD_POLICY=$(iptables -L FORWARD -n 2>/dev/null | head -1 | awk '{print $4}' | tr -d ')')
        OUTPUT_POLICY=$(iptables -L OUTPUT -n 2>/dev/null | head -1 | awk '{print $4}' | tr -d ')')

        echo -e "    INPUT:   $INPUT_POLICY"
        echo -e "    FORWARD: $FORWARD_POLICY"
        echo -e "    OUTPUT:  $OUTPUT_POLICY"

        log_result "INPUT policy: $INPUT_POLICY"
        log_result "FORWARD policy: $FORWARD_POLICY"
        log_result "OUTPUT policy: $OUTPUT_POLICY"

        # Проверка политик
        if [[ "$INPUT_POLICY" == "ACCEPT" ]]; then
            echo -e "${RED}[!] ВНИМАНИЕ: INPUT политика — ACCEPT${NC}"
            echo -e "${RED}    Рекомендация: iptables -P INPUT DROP${NC}"
            log_result "[CRITICAL] INPUT default policy is ACCEPT"
        else
            echo -e "${GREEN}[✓] INPUT политика: $INPUT_POLICY${NC}"
            log_result "[OK] INPUT policy: $INPUT_POLICY"
        fi

        if [[ "$FORWARD_POLICY" == "ACCEPT" ]]; then
            echo -e "${YELLOW}[!] FORWARD политика — ACCEPT${NC}"
            log_result "[WARNING] FORWARD default policy is ACCEPT"
        fi
        echo ""

        # Все правила
        echo -e "${BLUE}[*] Все правила iptables:${NC}"
        log_result "--- iptables Full Rules ---"

        IPTABLES_RULES=$(iptables -L -n -v --line-numbers 2>/dev/null)
        RULE_COUNT=$(iptables -L -n 2>/dev/null | grep -c -v -E "^Chain|^target|^$")

        if [[ $RULE_COUNT -eq 0 ]]; then
            echo -e "${RED}[!] ВНИМАНИЕ: Нет правил iptables!${NC}"
            echo -e "${RED}    Система не защищена файрволом${NC}"
            log_result "[CRITICAL] No iptables rules configured"
        else
            echo -e "    Всего правил: $RULE_COUNT"
            log_result "Total iptables rules: $RULE_COUNT"
            echo ""
            echo "$IPTABLES_RULES" | head -30 | tee -a "$REPORT_FILE"

            if [[ $RULE_COUNT -gt 30 ]]; then
                echo -e "${YELLOW}    ... (показано 30 из $RULE_COUNT правил)${NC}"
            fi
        fi
        echo ""

        # NAT таблица
        echo -e "${BLUE}[*] NAT правила:${NC}"
        log_result "--- iptables NAT Rules ---"

        NAT_RULES=$(iptables -t nat -L -n 2>/dev/null | grep -c -v -E "^Chain|^target|^$")
        if [[ $NAT_RULES -gt 0 ]]; then
            echo -e "    NAT правил: $NAT_RULES"
            iptables -t nat -L -n --line-numbers 2>/dev/null | tee -a "$REPORT_FILE"
        else
            echo -e "    NAT правил нет"
            log_result "No NAT rules"
        fi
        echo ""
    fi

    #----------------------------------------
    # 4. nftables
    #----------------------------------------
    if [[ $HAS_NFTABLES -eq 1 ]]; then
        echo -e "${BLUE}[*] Правила nftables:${NC}"
        log_result "--- nftables Rules ---"

        NFT_RULES=$(nft list ruleset 2>/dev/null)

        if [[ -n "$NFT_RULES" && "$NFT_RULES" != "" ]]; then
            NFT_TABLE_COUNT=$(nft list tables 2>/dev/null | wc -l)
            echo -e "    Таблиц: $NFT_TABLE_COUNT"
            log_result "nftables tables: $NFT_TABLE_COUNT"

            echo "$NFT_RULES" | head -30 | tee -a "$REPORT_FILE"
        else
            echo -e "${YELLOW}[!] nftables правила не настроены${NC}"
            log_result "[INFO] No nftables rules configured"
        fi
        echo ""
    fi

    #----------------------------------------
    # 5. firewalld
    #----------------------------------------
    if [[ $HAS_FIREWALLD -eq 1 ]]; then
        echo -e "${BLUE}[*] Статус firewalld:${NC}"
        log_result "--- firewalld Status ---"

        if systemctl is-active --quiet firewalld; then
            echo -e "${GREEN}[✓] firewalld активен${NC}"
            log_result "[OK] firewalld is active"

            # Активная зона
            echo -e "${BLUE}[*] Активные зоны:${NC}"
            firewall-cmd --get-active-zones 2>/dev/null | tee -a "$REPORT_FILE"

            # Разрешённые сервисы
            echo ""
            echo -e "${BLUE}[*] Разрешённые сервисы:${NC}"
            DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
            firewall-cmd --zone="$DEFAULT_ZONE" --list-all 2>/dev/null | tee -a "$REPORT_FILE"
        else
            echo -e "${YELLOW}[!] firewalld неактивен${NC}"
            log_result "[INFO] firewalld is inactive"
        fi
        echo ""
    fi

    #----------------------------------------
    # 6. Открытые порты без правил файрвола
    #----------------------------------------
    echo -e "${BLUE}[*] Открытые порты (слушающие):${NC}"
    log_result "--- Listening Ports ---"

    echo -e "    Протокол  Адрес               Порт    Процесс"
    echo -e "    ─────────────────────────────────────────────────"
    log_result "Proto  Address              Port    Process"

    ss -tlnp 2>/dev/null | tail -n +2 | while read -r line; do
        PROTO="TCP"
        ADDR=$(echo "$line" | awk '{print $4}')
        PORT=$(echo "$ADDR" | rev | cut -d: -f1 | rev)
        PROCESS=$(echo "$line" | grep -o '"[^"]*"' | head -1 | tr -d '"')
        PROCESS=${PROCESS:-"unknown"}

        echo -e "    $PROTO       $ADDR    $PORT    $PROCESS"
        log_result "$PROTO  $ADDR  $PORT  $PROCESS"
    done

    echo ""

    ss -ulnp 2>/dev/null | tail -n +2 | while read -r line; do
        PROTO="UDP"
        ADDR=$(echo "$line" | awk '{print $4}')
        PORT=$(echo "$ADDR" | rev | cut -d: -f1 | rev)
        PROCESS=$(echo "$line" | grep -o '"[^"]*"' | head -1 | tr -d '"')
        PROCESS=${PROCESS:-"unknown"}

        echo -e "    $PROTO       $ADDR    $PORT    $PROCESS"
        log_result "$PROTO  $ADDR  $PORT  $PROCESS"
    done
    echo ""

    # Подсчёт
    TCP_PORTS=$(ss -tlnp 2>/dev/null | tail -n +2 | wc -l)
    UDP_PORTS=$(ss -ulnp 2>/dev/null | tail -n +2 | wc -l)
    TOTAL_PORTS=$((TCP_PORTS + UDP_PORTS))

    echo -e "    TCP портов: $TCP_PORTS"
    echo -e "    UDP портов: $UDP_PORTS"
    echo -e "    Всего: $TOTAL_PORTS"
    log_result "TCP ports: $TCP_PORTS, UDP ports: $UDP_PORTS, Total: $TOTAL_PORTS"

    if [[ $TOTAL_PORTS -gt 15 ]]; then
        echo -e "${YELLOW}[!] Много открытых портов: $TOTAL_PORTS${NC}"
        echo -e "${YELLOW}    Рекомендация: закрыть неиспользуемые порты${NC}"
        log_result "[WARNING] Too many open ports: $TOTAL_PORTS"
    fi
    echo ""

    #----------------------------------------
    # 7. Проверка IP forwarding
    #----------------------------------------
    echo -e "${BLUE}[*] IP Forwarding:${NC}"
    log_result "--- IP Forwarding ---"

    IPV4_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    IPV6_FWD=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)

    if [[ "$IPV4_FWD" == "1" ]]; then
        echo -e "${YELLOW}[!] IPv4 forwarding ВКЛЮЧЁН${NC}"
        echo -e "${YELLOW}    Если это не роутер — отключите${NC}"
        log_result "[WARNING] IPv4 forwarding is enabled"
    else
        echo -e "${GREEN}[✓] IPv4 forwarding отключён${NC}"
        log_result "[OK] IPv4 forwarding is disabled"
    fi

    if [[ "$IPV6_FWD" == "1" ]]; then
        echo -e "${YELLOW}[!] IPv6 forwarding ВКЛЮЧЁН${NC}"
        log_result "[WARNING] IPv6 forwarding is enabled"
    else
        echo -e "${GREEN}[✓] IPv6 forwarding отключён${NC}"
        log_result "[OK] IPv6 forwarding is disabled"
    fi
    echo ""

    #----------------------------------------
    # 8. Рекомендации
    #----------------------------------------
    echo -e "${BLUE}[*] Рекомендации по файрволу:${NC}"
    log_result "--- Firewall Recommendations ---"

    echo -e "${CYAN}"
    cat << 'EOF'
    # Базовая настройка UFW:
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw enable

    # Или базовая настройка iptables:
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
EOF
    echo -e "${NC}"

    log_result "See firewall recommendations above"
    echo ""

    echo -e "${GREEN}[✓] Аудит файрвола завершён${NC}"
}

# Запуск
firewall_audit
