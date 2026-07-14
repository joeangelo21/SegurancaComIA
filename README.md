# 🛡️ SegurancaComIA — IPS Cognitivo Local com IA

Sistema experimental de **detecção e resposta a intrusão (IDS/IPS)** que roda inteiramente na sua máquina, sem depender de nenhum serviço em nuvem. Ele captura tráfego de rede em tempo real, filtra o que é suspeito e usa um modelo de linguagem local (via [Ollama](https://ollama.com)) para classificar e, se necessário, banir automaticamente o IP hostil.

---

## 🧠 Arquitetura

```
        Tráfego de Rede
               │
               ▼
      ┌─────────────────┐
      │  sentinela.py    │  captura pacotes (Scapy) e filtra whitelist
      └────────┬─────────┘
               │ escreve linhas de log
               ▼
   monitoramento_rede.log
               │
               ▼
      ┌─────────────────┐
      │  auditoria7.py   │  lê o log em tempo real (tail -f)
      └────────┬─────────┘
               │ se a linha contém termo suspeito
               ▼
      ┌─────────────────┐
      │  Ollama (local)  │  qwen2.5-coder:3b classifica o payload
      └────────┬─────────┘
               │ NORMAL / ATAQUE_FLOOD / ATAQUE_CRITICO
               ▼
   Score de risco por IP (persistido em risks.json)
               │
               ▼
   Threshold atingido? ──► banimento automático via iptables
```

Os dois programas rodam **em paralelo, como processos independentes**, conectados apenas pelo arquivo de log — isso mantém a captura de pacotes (que precisa de privilégios de root) isolada da análise por IA.

---

## ⚙️ Componentes

### 🔹 `sentinela.py` — Captura
- Captura pacotes IP/TCP em tempo real com Scapy
- Ignora endereços da `WHITELIST` já na captura, antes mesmo de logar
- Extrai um resumo seguro do payload TCP (até 100 bytes) para análise
- Grava cada evento em `monitoramento_rede.log` no formato:
  ```
  SRC: <ip> | SIZE: <bytes>B | PAYLOAD: <resumo>
  ```

### 🔹 `auditoria7.py` — Motor Cognitivo
- Lê o log continuamente (como um `tail -f`)
- Extrai e **valida** o IP de cada linha (regex com verificação de octetos 0–255, evitando falsos positivos)
- Aplica um filtro rápido por palavras-chave (`select`, `union`, `or 1=1`, `script`, `etc/passwd`, `alert`, `drop`) antes de gastar chamada de IA
- Quando o payload é suspeito, envia para o modelo local `qwen2.5-coder:3b` via API do Ollama, que responde com:
  - `NORMAL`
  - `ATAQUE_FLOOD`
  - `ATAQUE_CRITICO`
- Mantém um **score de risco por IP**, persistido em `risks.json` entre execuções
- Bane automaticamente via `iptables` quando o score atinge o `SCORE_THRESHOLD`
- Exibe um dashboard ao vivo no terminal com temperatura da GPU, volume de tráfego por IP, score de risco e os últimos veredictos

### 🔹 `instalar.sh` — Setup automatizado
Prepara todo o ambiente em uma única execução:
- Instala dependências de sistema (`python3`, `iptables`, `tcpdump`, `curl`)
- Cria um ambiente virtual Python (`venv/`) dentro da própria pasta do projeto
- Instala as libs Python necessárias (`scapy`, `requests`)
- Instala o Ollama (se ainda não estiver instalado) e baixa o modelo `qwen2.5-coder:3b`
- Cria os arquivos de log/score iniciais

### 🔹 `iniciar.sh` — Execução automatizada
Abre dois terminais automaticamente (detecta `mate-terminal`, `gnome-terminal`, `xfce4-terminal`, `konsole` ou `xterm`), um para o `sentinela.py` e outro para o `auditoria7.py`, já ativando o ambiente virtual em cada um.

---

## 📂 Estrutura do Projeto

```
.
├── sentinela.py             # Captura de pacotes e geração do log
├── auditoria7.py            # Motor cognitivo (IA + score + auto-ban)
├── instalar.sh              # Instala todas as dependências
├── iniciar.sh               # Sobe os dois programas automaticamente
├── .gitignore                # Ignora venv/, logs e score em runtime
└── README.md
```

Gerados em tempo de execução (ignorados pelo Git):
```
venv/                        # Ambiente virtual Python
monitoramento_rede.log       # Log de eventos de rede
risks.json                   # Score de risco persistido por IP
```

---

## 🚀 Como executar

### 1. Instalação (uma única vez)
```bash
chmod +x instalar.sh
./instalar.sh
```

### 2. Manter o modelo sempre carregado na GPU (opcional, recomendado)
Se o Ollama estiver rodando como serviço systemd:
```bash
sudo systemctl edit ollama.service
```
```ini
[Service]
Environment="OLLAMA_KEEP_ALIVE=-1"
```
```bash
sudo systemctl restart ollama
```

### 3. Rodar o sistema
```bash
chmod +x iniciar.sh
./iniciar.sh
```

Ou manualmente, em dois terminais:
```bash
# Terminal 1 — captura (precisa de sudo)
sudo venv/bin/python3 sentinela.py

# Terminal 2 — análise com IA
venv/bin/python3 auditoria7.py
```

---

## 🔧 Configuração

Os principais parâmetros ficam no topo de `auditoria7.py` e `sentinela.py`:

| Parâmetro | Descrição |
|---|---|
| `WHITELIST` | IPs que nunca são logados, analisados ou banidos |
| `MODELO` | Modelo Ollama usado na classificação (`qwen2.5-coder:3b`) |
| `SCORE_THRESHOLD` | Score de risco a partir do qual o IP é banido |
| `PALAVRAS_SUSPEITAS` | Termos que disparam a análise por IA |

---

## 🧪 Exemplo de linha de log

```
SRC: 192.168.1.17 | SIZE: 512B | PAYLOAD: IP / TCP 192.168.1.17:51422 > 10.0.0.1:80 S
```

## 🧠 Exemplo de veredicto no dashboard

```
✅ NORMAL: 192.168.1.17
⚠ SUSPEITO: 34.36.133.15 | Flood (2)
🚨 CRÍTICO: 185.125.190.121 | Payload Hostil!
⛔ BANIDO: 185.125.190.121
```

---

## ⚠️ Aviso

Este projeto é **experimental** e foi criado para fins de estudo de segurança de redes, IDS/IPS e integração com LLMs locais. Use apenas em ambientes controlados (laboratório, VM ou rede própria). O banimento automático via `iptables` altera regras de firewall do sistema — revise o `WHITELIST` antes de rodar em qualquer rede que você não queira arriscar travar.

---

## 👨‍💻 Autor

**Joelson Angelo**
Cybersecurity & Systems Development
