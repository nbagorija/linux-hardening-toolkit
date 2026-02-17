#!/bin/bash

#============================================
# Module: User Account Audit
# Description: Audits user accounts, password
#              policies, and access controls
#============================================

user_audit() {
    echo -e "${CYAN}[MODULE] Аудит пользователей${NC}"
    echo ""

    #----------------------------------------
    # 1. Пользователи с UID 0 (root-доступ)
    #----------------------------------------
    echo -e "${BLUE}[*] Пользователи с UID 0 (root-привилегии):${NC}"
    ROOT_USERS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    ROOT_COUNT=$(echo "$ROOT_USERS" | wc -l)

    log_result "--- Users with UID 0 ---"
    log_result "$ROOT_USERS"

    if [[ $ROOT_COUNT -gt 1 ]]; then
        echo -e "${RED}[!] ВНИМАНИЕ: Найдено $ROOT_COUNT пользователей с UID 0!${NC}"
        echo -e "${RED}    Только root должен иметь UID 0${NC}"
        log_result "[CRITICAL] Multiple users with UID 0: $ROOT_COUNT"
    else
        echo -e "${GREEN}[✓] Только root имеет UID 0${NC}"
        log_result "[OK] Only root has UID 0"
    fi
    echo ""

    #----------------------------------------
    # 2. Пользователи с пустым паролем
    #----------------------------------------
    echo -e "${BLUE}[*] Пользователи с пустым паролем:${NC}"
    EMPTY_PASS=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null)

    if [[ -n "$EMPTY_PASS" ]]; then
        echo -e "${RED}[!] ВНИМАНИЕ: Найдены пользователи с пустым паролем:${NC}"
        echo "$EMPTY_PASS" | while read -r user; do
            echo -e "${RED}    → $user${NC}"
            log_result "[CRITICAL] Empty password: $user"
        done
    else
        echo -e "${GREEN}[✓] Пользователей с пустым паролем не найдено${NC}"
        log_result "[OK] No users with empty passwords"
    fi
    echo ""

    #----------------------------------------
    # 3. Все обычные пользователи (UID >= 1000)
    #----------------------------------------
    echo -e "${BLUE}[*] Обычные пользователи (UID >= 1000):${NC}"
    log_result "--- Regular Users ---"

    REGULAR_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1 " (UID: " $3 ", Shell: " $7 ")"}' /etc/passwd)

    if [[ -n "$REGULAR_USERS" ]]; then
        echo "$REGULAR_USERS" | while read -r line; do
            echo -e "    $line"
            log_result "$line"
        done
    else
        echo -e "${YELLOW}[!] Обычных пользователей не найдено${NC}"
    fi

    REGULAR_COUNT=$(awk -F: '$3 >= 1000 && $3 < 65534' /etc/passwd | wc -l)
    log_result "Total regular users: $REGULAR_COUNT"
    echo ""

    #----------------------------------------
    # 4. Пользователи с доступом к shell
    #----------------------------------------
    echo -e "${BLUE}[*] Пользователи с доступом к shell:${NC}"
    log_result "--- Users with shell access ---"

    SHELL_USERS=$(grep -v -E "nologin|false|sync|halt|shutdown" /etc/passwd | awk -F: '{print $1 " → " $7}')

    echo "$SHELL_USERS" | while read -r line; do
        echo -e "    $line"
        log_result "$line"
    done

    SHELL_COUNT=$(grep -v -E "nologin|false|sync|halt|shutdown" /etc/passwd | wc -l)
    if [[ $SHELL_COUNT -gt 5 ]]; then
        echo -e "${YELLOW}[!] Много пользователей с доступом к shell: $SHELL_COUNT${NC}"
        log_result "[WARNING] Many users with shell access: $SHELL_COUNT"
    else
        echo -e "${GREEN}[✓] Пользователей с shell: $SHELL_COUNT${NC}"
        log_result "[OK] Users with shell access: $SHELL_COUNT"
    fi
    echo ""

    #----------------------------------------
    # 5. Группа sudo
    #----------------------------------------
    echo -e "${BLUE}[*] Пользователи в группе sudo:${NC}"
    log_result "--- Sudo Group Members ---"

    SUDO_USERS=$(getent group sudo 2>/dev/null | cut -d: -f4)

    if [[ -n "$SUDO_USERS" ]]; then
        echo -e "    $SUDO_USERS"
        log_result "Sudo users: $SUDO_USERS"

        SUDO_COUNT=$(echo "$SUDO_USERS" | tr ',' '\n' | wc -l)
        if [[ $SUDO_COUNT -gt 3 ]]; then
            echo -e "${YELLOW}[!] Много пользователей в группе sudo: $SUDO_COUNT${NC}"
            log_result "[WARNING] Many sudo users: $SUDO_COUNT"
        else
            echo -e "${GREEN}[✓] Количество sudo пользователей: $SUDO_COUNT${NC}"
            log_result "[OK] Sudo users count: $SUDO_COUNT"
        fi
    else
        echo -e "${YELLOW}[!] Группа sudo пуста или не существует${NC}"
        log_result "[INFO] No sudo group members found"
    fi
    echo ""

    #----------------------------------------
    # 6. Проверка /etc/sudoers
    #----------------------------------------
    echo -e "${BLUE}[*] Проверка файла sudoers:${NC}"
    log_result "--- Sudoers Check ---"

    # NOPASSWD записи
    NOPASSWD=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#")

    if [[ -n "$NOPASSWD" ]]; then
        echo -e "${RED}[!] Найдены правила NOPASSWD:${NC}"
        echo "$NOPASSWD" | while read -r line; do
            echo -e "${RED}    → $line${NC}"
            log_result "[WARNING] NOPASSWD rule: $line"
        done
    else
        echo -e "${GREEN}[✓] Правил NOPASSWD не найдено${NC}"
        log_result "[OK] No NOPASSWD rules found"
    fi
    echo ""

    #----------------------------------------
    # 7. Последние входы в систему
    #----------------------------------------
    echo -e "${BLUE}[*] Последние входы в систему:${NC}"
    log_result "--- Last Logins ---"

    if command -v lastlog &>/dev/null; then
        lastlog 2>/dev/null | grep -v "Never" | head -10 | tee -a "$REPORT_FILE"
    fi
    echo ""

    #----------------------------------------
    # 8. Неудачные попытки входа
    #----------------------------------------
    echo -e "${BLUE}[*] Неудачные попытки входа:${NC}"
    log_result "--- Failed Login Attempts ---"

    if command -v lastb &>/dev/null; then
        FAILED_COUNT=$(lastb 2>/dev/null | wc -l)
        if [[ $FAILED_COUNT -gt 10 ]]; then
            echo -e "${RED}[!] Обнаружено $FAILED_COUNT неудачных попыток входа!${NC}"
            log_result "[WARNING] Failed login attempts: $FAILED_COUNT"
            echo -e "${BLUE}    Последние 5 попыток:${NC}"
            lastb 2>/dev/null | head -5 | tee -a "$REPORT_FILE"
        else
            echo -e "${GREEN}[✓] Неудачных попыток входа: $FAILED_COUNT${NC}"
            log_result "[OK] Failed login attempts: $FAILED_COUNT"
        fi
    fi
    echo ""

    #----------------------------------------
    # 9. Политика паролей
    #----------------------------------------
    echo -e "${BLUE}[*] Политика паролей (/etc/login.defs):${NC}"
    log_result "--- Password Policy ---"

    if [[ -f /etc/login.defs ]]; then
        PASS_MAX=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        PASS_MIN=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
        PASS_LEN=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
        PASS_WARN=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')

        echo -e "    Макс. срок пароля:  $PASS_MAX дней"
        echo -e "    Мин. срок пароля:   $PASS_MIN дней"
        echo -e "    Мин. длина пароля:  $PASS_LEN символов"
        echo -e "    Предупреждение:     $PASS_WARN дней"

        log_result "PASS_MAX_DAYS: $PASS_MAX"
        log_result "PASS_MIN_DAYS: $PASS_MIN"
        log_result "PASS_MIN_LEN: $PASS_LEN"
        log_result "PASS_WARN_AGE: $PASS_WARN"

        # Проверки
        if [[ "$PASS_MAX" -gt 90 || "$PASS_MAX" == "99999" ]]; then
            echo -e "${YELLOW}[!] Рекомендуется PASS_MAX_DAYS <= 90${NC}"
            log_result "[WARNING] PASS_MAX_DAYS too high"
        fi

        if [[ "$PASS_MIN" -lt 7 ]]; then
            echo -e "${YELLOW}[!] Рекомендуется PASS_MIN_DAYS >= 7${NC}"
            log_result "[WARNING] PASS_MIN_DAYS too low"
        fi
    else
        echo -e "${RED}[!] Файл /etc/login.defs не найден${NC}"
        log_result "[ERROR] /etc/login.defs not found"
    fi
    echo ""

    #----------------------------------------
    # 10. Заблокированные аккаунты
    #----------------------------------------
    echo -e "${BLUE}[*] Заблокированные аккаунты:${NC}"
    log_result "--- Locked Accounts ---"

    LOCKED=$(awk -F: '$2 ~ /^!/ || $2 ~ /^\*/ {print $1}' /etc/shadow 2>/dev/null | grep -v -E "^(daemon|bin|sys|games|man|lp|mail|news|uucp|proxy|backup|list|irc|gnats|nobody)")

    if [[ -n "$LOCKED" ]]; then
        LOCKED_COUNT=$(echo "$LOCKED" | wc -l)
        echo -e "    Заблокированных системных аккаунтов: $LOCKED_COUNT"
        log_result "Locked accounts: $LOCKED_COUNT"
    fi
    echo ""

    echo -e "${GREEN}[✓] Аудит пользователей завершён${NC}"
}

# Запуск
user_audit
