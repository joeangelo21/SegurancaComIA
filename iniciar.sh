#!/bin/bash
set -e

# Pasta onde o próprio iniciar.sh está (ex: ~/AuditoriaComIA)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$DIR/venv/bin/python3"

echo "=============================================="
echo " Iniciando Sentinela + Auditoria7"
echo " Pasta do projeto: $DIR"
echo "=============================================="

if [ ! -f "$VENV_PY" ]; then
    echo "[!] Ambiente virtual não encontrado em $DIR/venv."
    echo "    Rode primeiro: ./instalar.sh"
    exit 1
fi

# Comando de cada programa
CMD_SENTINELA="cd '$DIR' && sudo '$VENV_PY' sentinela.py; echo; echo '[Sentinela encerrado. Pressione Enter para fechar]'; read"
CMD_AUDITORIA="cd '$DIR' && '$VENV_PY' auditoria7.py; echo; echo '[Auditoria7 encerrado. Pressione Enter para fechar]'; read"

abrir_terminal() {
    local titulo="$1"
    local comando="$2"

    if command -v mate-terminal &> /dev/null; then
        mate-terminal --title="$titulo" -- bash -c "$comando"
    elif command -v gnome-terminal &> /dev/null; then
        gnome-terminal --title="$titulo" -- bash -c "$comando"
    elif command -v xfce4-terminal &> /dev/null; then
        xfce4-terminal --title="$titulo" -e "bash -c \"$comando\""
    elif command -v konsole &> /dev/null; then
        konsole --new-tab -p tabtitle="$titulo" -e bash -c "$comando"
    elif command -v xterm &> /dev/null; then
        xterm -T "$titulo" -e bash -c "$comando" &
    else
        echo "[!] Nenhum emulador de terminal conhecido foi encontrado."
        echo "    Rode manualmente em dois terminais:"
        echo "    1) sudo $VENV_PY sentinela.py"
        echo "    2) $VENV_PY auditoria7.py"
        exit 1
    fi
}

echo "[1/2] Abrindo terminal do Sentinela (captura de pacotes)..."
abrir_terminal "Sentinela" "$CMD_SENTINELA"

# Pequena pausa para o Sentinela iniciar antes do Auditoria7
sleep 2

echo "[2/2] Abrindo terminal do Auditoria7 (motor de análise com IA)..."
abrir_terminal "Auditoria7" "$CMD_AUDITORIA"

echo ""
echo "Pronto! Dois terminais foram abertos:"
echo "  - Sentinela: vai pedir sua senha de sudo (captura de pacotes)"
echo "  - Auditoria7: dashboard com os veredictos em tempo real"
echo ""
echo "Para parar: feche as janelas ou use Ctrl+C em cada uma."
