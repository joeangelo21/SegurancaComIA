#!/bin/bash
set -e

# Pasta onde o próprio instalar.sh está (ex: ~/AuditoriaComIA)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================="
echo " Instalador - Sentinela + Auditoria7 (IPS local)"
echo " Pasta do projeto: $DIR"
echo "=============================================="

# ------------------------------------------------------------
# 1. Pacotes de sistema
# ------------------------------------------------------------
echo "[1/5] Atualizando repositórios e instalando pacotes de sistema..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv iptables tcpdump curl

# ------------------------------------------------------------
# 2. Ambiente virtual Python (criado dentro da própria pasta do projeto)
# ------------------------------------------------------------
echo "[2/5] Criando ambiente virtual em $DIR/venv..."
python3 -m venv "$DIR/venv"
source "$DIR/venv/bin/activate"

# ------------------------------------------------------------
# 3. Dependências Python
# ------------------------------------------------------------
echo "[3/5] Instalando dependências Python (scapy, requests)..."
pip install --upgrade pip
pip install scapy requests

# ------------------------------------------------------------
# 4. Ollama (IA local) + modelo qwen2.5-coder:3b
# ------------------------------------------------------------
echo "[4/5] Verificando Ollama..."
if ! command -v ollama &> /dev/null; then
    echo "Ollama não encontrado. Instalando..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "Ollama já instalado."
fi

echo "Iniciando serviço do Ollama em background (se ainda não estiver rodando)..."
echo "  -> Com OLLAMA_KEEP_ALIVE=-1, o modelo fica sempre carregado na GPU"
echo "     (evita o atraso de recarregar o modelo a cada análise)."
if ! pgrep -x "ollama" > /dev/null; then
    OLLAMA_KEEP_ALIVE=-1 nohup ollama serve > /tmp/ollama.log 2>&1 &
    sleep 3
else
    echo "  -> Ollama já estava rodando. Se quiser aplicar o keep-alive,"
    echo "     pare o serviço atual e suba de novo com:"
    echo "     OLLAMA_KEEP_ALIVE=-1 ollama serve"
fi

echo "Baixando modelo qwen2.5-coder:3b (pode demorar dependendo da conexão)..."
ollama pull qwen2.5-coder:3b

# ------------------------------------------------------------
# 5. Preparar arquivos de log/score dentro da pasta do projeto
# ------------------------------------------------------------
echo "[5/5] Preparando arquivos de log dentro de $DIR..."
touch "$DIR/monitoramento_rede.log"
echo "{}" > "$DIR/risks.json"

echo ""
echo "=============================================="
echo " Instalação concluída!"
echo "=============================================="
echo ""
echo "Para rodar (dentro da pasta $DIR):"
echo ""
echo "  1) Ative o ambiente virtual em cada terminal novo:"
echo "     source venv/bin/activate"
echo ""
echo "  2) Em um terminal, capture o tráfego (precisa de sudo por causa do scapy):"
echo "     sudo venv/bin/python3 sentinela.py"
echo ""
echo "  3) Em outro terminal, rode o motor de análise:"
echo "     python3 auditoria7.py"
echo ""
echo "  Obs: 'auditoria7.py' usa 'sudo iptables' para banir IPs automaticamente,"
echo "  então pode pedir sua senha na hora do primeiro ban."
echo ""
echo "  Se o Ollama estiver rodando como serviço systemd (ollama.service),"
echo "  o jeito certo de manter o modelo sempre carregado na GPU é:"
echo ""
echo "     sudo systemctl edit ollama.service"
echo ""
echo "  E adicionar estas linhas no arquivo que abrir:"
echo ""
echo "     [Service]"
echo "     Environment=\"OLLAMA_KEEP_ALIVE=-1\""
echo ""
echo "  Depois reinicie o serviço:"
echo ""
echo "     sudo systemctl restart ollama"
echo ""
