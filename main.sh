#!/bin/bash

#============================================
# Linux Hardening Toolkit
# Author: nbagorija
# Description: Automated Linux security
#              auditing and hardening tool
# Based on: CIS Benchmarks
#============================================

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Директории
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
REPORTS_DIR="$SCRIPT_DIR/reports"

# Файл отчёта
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$REPORTS_DIR/audit_report_$TIMESTAMP.txt"

#============================================
# Функции
#============================================

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║       Linux Hardening Toolkit v1.0       ║"
    echo "║         Security Audit & Hardening       ║"
    echo "║              by nbagorija                 ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Этот скрипт требует root-привилегий${NC}"
        echo -e "${YELLOW}[*] Запустите: sudo ./main.sh${NC}"
        exit 1
    fi
}

log_result() {
    echo "$1" | tee -a "$REPORT_FILE"
}

separator() {
    log_result "$(printf '=%.0s' {1..50})"
}

show_menu() {
    echo -e "${GREEN}[Выберите действие]${NC}"
    echo ""
    echo "  1) Полный аудит безопасности"
    echo "  2) Сбор информации о системе"
    echo "  3) Аудит пользователей"
    echo "  4) Аудит SSH"
    echo "  5) Аудит файрвола"
    echo "  6) Проверка прав файлов"
    echo "  7) Сетевой аудит"
    echo "  8) Аудит сервисов"
    echo "  9) Аудит логирования"
    echo "  0) Выход"
    echo ""
    read -p "Ваш выбор: " choice
}

run_module() {
    local module="$1"
    local module_path="$MODULES_DIR/$module"

    if [[ -f "$module_path" ]]; then
        echo -e "${BLUE}[*] Запуск модуля: $module${NC}"
        separator
        source "$module_path"
        separator
        echo ""
    else
        echo -e "${RED}[!] Модуль не найден: $module${NC}"
    fi
}

run_full_audit() {
    echo -e "${YELLOW}[*] Запуск полного аудита безопасности...${NC}"
    echo ""
    log_result "Отчёт аудита безопасности — $(date)"
    log_result "Хост: $(hostname)"
    separator

    for module in "$MODULES_DIR"/*.sh; do
        source "$module"
        echo ""
    done

    echo -e "${GREEN}[✓] Полный аудит завершён!${NC}"
    echo -e "${GREEN}[✓] Отчёт сохранён: $REPORT_FILE${NC}"
}

#============================================
# Основная логика
#============================================

banner
check_root

# Создаём директорию для отчётов
mkdir -p "$REPORTS_DIR"

# Инициализируем отчёт
echo "=== Linux Hardening Toolkit — Отчёт ===" > "$REPORT_FILE"
echo "Дата: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

while true; do
    show_menu

    case $choice in
        1) run_full_audit ;;
        2) run_module "01_system_info.sh" ;;
        3) run_module "02_user_audit.sh" ;;
        4) run_module "03_ssh_hardening.sh" ;;
        5) run_module "04_firewall.sh" ;;
        6) run_module "05_file_permissions.sh" ;;
        7) run_module "06_network_audit.sh" ;;
        8) run_module "07_service_audit.sh" ;;
        9) run_module "08_logging.sh" ;;
        0)
            echo -e "${GREEN}[*] До свидания!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Неверный выбор${NC}"
            ;;
    esac
done
