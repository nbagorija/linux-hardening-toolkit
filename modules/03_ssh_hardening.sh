#!/bin/bash

#============================================
# Module: SSH Hardening Audit
# Description: Analyzes SSH configuration
#              and provides recommendations
#============================================

ssh_audit() {
    echo -e "${CYAN}[MODULE] Аудит SSH${NC}"
    echo ""

    # Путь к конфигу SSH
    SSHD_CONFIG="/etc/ssh/sshd_config"
    SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"

    #----------------------------------------
    # 1. Проверка установки SSH
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка SSH сервера:${NC}"
    log_result "--- SSH Server Check ---"

    if command -v sshd &>/dev/null; then
        SSH_VERSION=$(sshd -V 2>&1 | head -1)
        echo -e "${GREEN}[✓] SSH сервер установлен${NC}"
        log_result "[OK] SSH server installed"
        log_result "Version: $SSH_VERSION"
    else
        echo -e "${YELLOW}[!] SSH сервер не установлен${NC}"
        log_result "[INFO] SSH server not installed"
        echo -e "${GREEN}[✓] Аудит SSH не требуется${NC}"
        return
    fi
    echo ""

    #----------------------------------------
    # 2. Статус SSH сервиса
    #----------------------------------------
    echo -e "${BLUE}[*] Статус SSH сервиса:${NC}"
    log_result "--- SSH Service Status ---"

    if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
        echo -e "${YELLOW}[!] SSH сервис ЗАПУЩЕН${NC}"
        log_result "[INFO] SSH service is running"

        # Проверяем порт
        SSH_PORT=$(ss -tlnp | grep sshd | awk '{print $4}' | head -1)
        echo -e "    Слушает на: $SSH_PORT"
        log_result "Listening on: $SSH_PORT"
    else
        echo -e "${GREEN}[✓] SSH сервис остановлен${NC}"
        log_result "[OK] SSH service is stopped"
    fi

    # Автозапуск
    if systemctl is-enabled --quiet sshd 2>/dev/null || systemctl is-enabled --quiet ssh 2>/dev/null; then
        echo -e "${YELLOW}[!] SSH включён в автозапуск${NC}"
        log_result "[INFO] SSH is enabled at boot"
    else
        echo -e "${GREEN}[✓] SSH не в автозапуске${NC}"
        log_result "[OK] SSH is not enabled at boot"
    fi
    echo ""

    #----------------------------------------
    # 3. Проверка конфигурационного файла
    #----------------------------------------
    if [[ ! -f "$SSHD_CONFIG" ]]; then
        echo -e "${RED}[!] Файл $SSHD_CONFIG не найден${NC}"
        log_result "[ERROR] $SSHD_CONFIG not found"
        return
    fi

    echo -e "${BLUE}[*] Анализ $SSHD_CONFIG:${NC}"
    log_result "--- SSH Configuration Analysis ---"
    echo ""

    # Функция для чтения параметра из конфига
    get_ssh_param() {
        local param="$1"
        local value

        # Сначала проверяем в доп. конфигах
        if [[ -d "$SSHD_CONFIG_DIR" ]]; then
            value=$(grep -rhi "^$param" "$SSHD_CONFIG_DIR" 2>/dev/null | tail -1 | awk '{print $2}')
        fi

        # Если не найдено — ищем в основном конфиге
        if [[ -z "$value" ]]; then
            value=$(grep -i "^$param" "$SSHD_CONFIG" 2>/dev/null | tail -1 | awk '{print $2}')
        fi

        # Если закомментировано — ищем дефолт
        if [[ -z "$value" ]]; then
            value=$(grep -i "^#$param" "$SSHD_CONFIG" 2>/dev/null | tail -1 | awk '{print $2}')
            if [[ -n "$value" ]]; then
                value="$value (default)"
            fi
        fi

        echo "$value"
    }

    #----------------------------------------
    # 4. Порт SSH
    #----------------------------------------
    echo -e "${BLUE}[*] Порт SSH:${NC}"
    SSH_PORT_CFG=$(get_ssh_param "Port")
    SSH_PORT_CFG=${SSH_PORT_CFG:-"22 (default)"}
    log_result "Port: $SSH_PORT_CFG"

    if [[ "$SSH_PORT_CFG" == "22" || "$SSH_PORT_CFG" == "22 (default)" ]]; then
        echo -e "${YELLOW}[!] SSH использует стандартный порт 22${NC}"
        echo -e "${YELLOW}    Рекомендация: сменить на нестандартный порт${NC}"
        log_result "[WARNING] SSH using default port 22"
    else
        echo -e "${GREEN}[✓] SSH использует нестандартный порт: $SSH_PORT_CFG${NC}"
        log_result "[OK] SSH using non-default port: $SSH_PORT_CFG"
    fi
    echo ""

    #----------------------------------------
    # 5. Root логин
    #----------------------------------------
    echo -e "${BLUE}[*] Root логин через SSH:${NC}"
    PERMIT_ROOT=$(get_ssh_param "PermitRootLogin")
    PERMIT_ROOT=${PERMIT_ROOT:-"prohibit-password (default)"}
    log_result "PermitRootLogin: $PERMIT_ROOT"

    case "$PERMIT_ROOT" in
        "no")
            echo -e "${GREEN}[✓] Root логин запрещён${NC}"
            log_result "[OK] Root login is disabled"
            ;;
        "prohibit-password"|"prohibit-password (default)"|"without-password")
            echo -e "${YELLOW}[!] Root логин разрешён только по ключу${NC}"
            echo -e "${YELLOW}    Рекомендация: установить 'no'${NC}"
            log_result "[WARNING] Root login allowed with key only"
            ;;
        "yes")
            echo -e "${RED}[!] ВНИМАНИЕ: Root логин РАЗРЕШЁН!${NC}"
            echo -e "${RED}    Рекомендация: PermitRootLogin no${NC}"
            log_result "[CRITICAL] Root login is enabled"
            ;;
        *)
            echo -e "${YELLOW}[?] Значение: $PERMIT_ROOT${NC}"
            log_result "[INFO] PermitRootLogin: $PERMIT_ROOT"
            ;;
    esac
    echo ""

    #----------------------------------------
    # 6. Парольная аутентификация
    #----------------------------------------
    echo -e "${BLUE}[*] Парольная аутентификация:${NC}"
    PASS_AUTH=$(get_ssh_param "PasswordAuthentication")
    PASS_AUTH=${PASS_AUTH:-"yes (default)"}
    log_result "PasswordAuthentication: $PASS_AUTH"

    if [[ "$PASS_AUTH" == "no" ]]; then
        echo -e "${GREEN}[✓] Парольная аутентификация отключена${NC}"
        log_result "[OK] Password authentication is disabled"
    else
        echo -e "${YELLOW}[!] Парольная аутентификация включена${NC}"
        echo -e "${YELLOW}    Рекомендация: использовать SSH-ключи${NC}"
        log_result "[WARNING] Password authentication is enabled"
    fi
    echo ""

    #----------------------------------------
    # 7. Аутентификация по ключам
    #----------------------------------------
    echo -e "${BLUE}[*] Аутентификация по ключам:${NC}"
    PUBKEY_AUTH=$(get_ssh_param "PubkeyAuthentication")
    PUBKEY_AUTH=${PUBKEY_AUTH:-"yes (default)"}
    log_result "PubkeyAuthentication: $PUBKEY_AUTH"

    if [[ "$PUBKEY_AUTH" == "yes" || "$PUBKEY_AUTH" == "yes (default)" ]]; then
        echo -e "${GREEN}[✓] Аутентификация по ключам включена${NC}"
        log_result "[OK] Public key authentication is enabled"
    else
        echo -e "${RED}[!] Аутентификация по ключам отключена!${NC}"
        log_result "[CRITICAL] Public key authentication is disabled"
    fi
    echo ""

    #----------------------------------------
    # 8. Пустые пароли
    #----------------------------------------
    echo -e "${BLUE}[*] Пустые пароли:${NC}"
    EMPTY_PASS=$(get_ssh_param "PermitEmptyPasswords")
    EMPTY_PASS=${EMPTY_PASS:-"no (default)"}
    log_result "PermitEmptyPasswords: $EMPTY_PASS"

    if [[ "$EMPTY_PASS" == "no" || "$EMPTY_PASS" == "no (default)" ]]; then
        echo -e "${GREEN}[✓] Пустые пароли запрещены${NC}"
        log_result "[OK] Empty passwords are not permitted"
    else
        echo -e "${RED}[!] ВНИМАНИЕ: Пустые пароли разрешены!${NC}"
        log_result "[CRITICAL] Empty passwords are permitted"
    fi
    echo ""

    #----------------------------------------
    # 9. Протокол SSH
    #----------------------------------------
    echo -e "${BLUE}[*] Протокол SSH:${NC}"
    SSH_PROTOCOL=$(get_ssh_param "Protocol")
    SSH_PROTOCOL=${SSH_PROTOCOL:-"2 (default)"}
    log_result "Protocol: $SSH_PROTOCOL"

    if [[ "$SSH_PROTOCOL" == "2" || "$SSH_PROTOCOL" == "2 (default)" ]]; then
        echo -e "${GREEN}[✓] Используется протокол SSH 2${NC}"
        log_result "[OK] SSH Protocol 2 is used"
    else
        echo -e "${RED}[!] Используется устаревший протокол!${NC}"
        log_result "[CRITICAL] Outdated SSH protocol"
    fi
    echo ""

    #----------------------------------------
    # 10. Таймауты и попытки
    #----------------------------------------
    echo -e "${BLUE}[*] Таймауты и ограничения:${NC}"
    log_result "--- Timeouts and Limits ---"

    # LoginGraceTime
    LOGIN_GRACE=$(get_ssh_param "LoginGraceTime")
    LOGIN_GRACE=${LOGIN_GRACE:-"120 (default)"}
    echo -e "    LoginGraceTime:     $LOGIN_GRACE"
    log_result "LoginGraceTime: $LOGIN_GRACE"

    # MaxAuthTries
    MAX_AUTH=$(get_ssh_param "MaxAuthTries")
    MAX_AUTH=${MAX_AUTH:-"6 (default)"}
    echo -e "    MaxAuthTries:       $MAX_AUTH"
    log_result "MaxAuthTries: $MAX_AUTH"

    MAX_AUTH_NUM=$(echo "$MAX_AUTH" | grep -o '[0-9]*')
    if [[ "$MAX_AUTH_NUM" -gt 4 ]]; then
        echo -e "${YELLOW}    [!] Рекомендация: MaxAuthTries <= 4${NC}"
        log_result "[WARNING] MaxAuthTries too high"
    fi

    # MaxSessions
    MAX_SESSIONS=$(get_ssh_param "MaxSessions")
    MAX_SESSIONS=${MAX_SESSIONS:-"10 (default)"}
    echo -e "    MaxSessions:        $MAX_SESSIONS"
    log_result "MaxSessions: $MAX_SESSIONS"

    # ClientAliveInterval
    ALIVE_INTERVAL=$(get_ssh_param "ClientAliveInterval")
    ALIVE_INTERVAL=${ALIVE_INTERVAL:-"0 (default)"}
    echo -e "    ClientAliveInterval: $ALIVE_INTERVAL"
    log_result "ClientAliveInterval: $ALIVE_INTERVAL"

    if [[ "$ALIVE_INTERVAL" == "0" || "$ALIVE_INTERVAL" == "0 (default)" ]]; then
        echo -e "${YELLOW}    [!] Рекомендация: установить ClientAliveInterval 300${NC}"
        log_result "[WARNING] ClientAliveInterval not set"
    fi

    # ClientAliveCountMax
    ALIVE_COUNT=$(get_ssh_param "ClientAliveCountMax")
    ALIVE_COUNT=${ALIVE_COUNT:-"3 (default)"}
    echo -e "    ClientAliveCountMax: $ALIVE_COUNT"
    log_result "ClientAliveCountMax: $ALIVE_COUNT"
    echo ""

    #----------------------------------------
    # 11. X11 Forwarding
    #----------------------------------------
    echo -e "${BLUE}[*] X11 Forwarding:${NC}"
    X11_FWD=$(get_ssh_param "X11Forwarding")
    X11_FWD=${X11_FWD:-"no (default)"}
    log_result "X11Forwarding: $X11_FWD"

    if [[ "$X11_FWD" == "yes" ]]; then
        echo -e "${YELLOW}[!] X11 Forwarding включён${NC}"
        echo -e "${YELLOW}    Рекомендация: отключить если не используется${NC}"
        log_result "[WARNING] X11 Forwarding is enabled"
    else
        echo -e "${GREEN}[✓] X11 Forwarding отключён${NC}"
        log_result "[OK] X11 Forwarding is disabled"
    fi
    echo ""

    #----------------------------------------
    # 12. AllowUsers / AllowGroups
    #----------------------------------------
    echo -e "${BLUE}[*] Ограничение доступа:${NC}"
    log_result "--- Access Restrictions ---"

    ALLOW_USERS=$(get_ssh_param "AllowUsers")
    ALLOW_GROUPS=$(get_ssh_param "AllowGroups")
    DENY_USERS=$(get_ssh_param "DenyUsers")
    DENY_GROUPS=$(get_ssh_param "DenyGroups")

    if [[ -n "$ALLOW_USERS" ]]; then
        echo -e "${GREEN}[✓] AllowUsers: $ALLOW_USERS${NC}"
        log_result "[OK] AllowUsers: $ALLOW_USERS"
    elif [[ -n "$ALLOW_GROUPS" ]]; then
        echo -e "${GREEN}[✓] AllowGroups: $ALLOW_GROUPS${NC}"
        log_result "[OK] AllowGroups: $ALLOW_GROUPS"
    else
        echo -e "${YELLOW}[!] AllowUsers/AllowGroups не настроены${NC}"
        echo -e "${YELLOW}    Рекомендация: ограничить доступ по SSH${NC}"
        log_result "[WARNING] No AllowUsers/AllowGroups configured"
    fi

    if [[ -n "$DENY_USERS" ]]; then
        echo -e "    DenyUsers: $DENY_USERS"
        log_result "DenyUsers: $DENY_USERS"
    fi
    if [[ -n "$DENY_GROUPS" ]]; then
        echo -e "    DenyGroups: $DENY_GROUPS"
        log_result "DenyGroups: $DENY_GROUPS"
    fi
    echo ""

    #----------------------------------------
    # 13. SSH ключи
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка SSH ключей:${NC}"
    log_result "--- SSH Keys Check ---"

    # Проверяем authorized_keys для всех пользователей
    FOUND_KEYS=0
    while IFS=: read -r username _ uid _ _ homedir _; do
        if [[ $uid -ge 1000 || "$username" == "root" ]]; then
            AUTH_KEYS="$homedir/.ssh/authorized_keys"
            if [[ -f "$AUTH_KEYS" ]]; then
                KEY_COUNT=$(wc -l < "$AUTH_KEYS")
                echo -e "    $username: $KEY_COUNT ключ(ей) в $AUTH_KEYS"
                log_result "$username: $KEY_COUNT key(s) in $AUTH_KEYS"
                FOUND_KEYS=1

                # Проверяем права на файл
                PERMS=$(stat -c "%a" "$AUTH_KEYS")
                if [[ "$PERMS" != "600" && "$PERMS" != "644" ]]; then
                    echo -e "${RED}    [!] Неправильные права: $PERMS (должно быть 600)${NC}"
                    log_result "[WARNING] Wrong permissions on $AUTH_KEYS: $PERMS"
                fi
            fi
        fi
    done < /etc/passwd

    if [[ $FOUND_KEYS -eq 0 ]]; then
        echo -e "${YELLOW}[!] SSH ключи не найдены ни у одного пользователя${NC}"
        log_result "[INFO] No authorized_keys found"
    fi
    echo ""

    #----------------------------------------
    # 14. Итоговые рекомендации
    #----------------------------------------
    echo -e "${BLUE}[*] Рекомендуемая конфигурация SSH:${NC}"
    log_result "--- Recommended SSH Configuration ---"

    echo -e "${CYAN}"
    cat << 'EOF'
    # /etc/ssh/sshd_config recommended settings:
    Port 2222                    # Нестандартный порт
    PermitRootLogin no           # Запрет root логина
    PasswordAuthentication no    # Только ключи
    PubkeyAuthentication yes     # Включить ключи
    PermitEmptyPasswords no      # Запрет пустых паролей
    MaxAuthTries 4               # Макс попыток
    ClientAliveInterval 300      # Таймаут 5 минут
    ClientAliveCountMax 2        # Макс пропущенных пингов
    X11Forwarding no             # Отключить X11
    AllowUsers your_user         # Только определённые юзеры
    Protocol 2                   # Только SSH2
EOF
    echo -e "${NC}"

    log_result "See recommended configuration above"
    echo ""

    echo -e "${GREEN}[✓] Аудит SSH завершён${NC}"
}

# Запуск
ssh_audit
