# 🛡️ SegurancaComIA — AI-Driven Intrusion Detection System

## 📌 Visão Geral

O **SegurancaComIA** é um sistema experimental de detecção de intrusão (IDS) que combina:

- Captura de tráfego de rede em tempo real (Scapy)
- Pipeline de eventos estruturados em JSON
- Análise inteligente com IA local (Ollama + Qwen 2.5 Coder)
- Sistema de feedback para bloqueio dinâmico de IPs

O objetivo do projeto é simular um **SOC (Security Operations Center) local leve**, utilizando inteligência artificial para classificação de tráfego.

---

## 🧠 Arquitetura


Rede → Sentinela (Scapy) → Eventos JSON → IA Local (Ollama)
↓
Decisão (NORMAL / ATAQUE)
↓
Feedback Loop (banimento de IP)


---

## ⚙️ Componentes

### 🔹 1. Sentinela (sentinela.py)

Responsável por:

- Capturar pacotes de rede em tempo real
- Filtrar IPs (whitelist / blacklist)
- Gerar eventos estruturados em JSON
- Enviar eventos para buffer local (`/tmp/traffic_buffer`)
- Manter histórico de volume de tráfego por IP

---

### 🔹 2. IA Analyzer (auditoria.py)

Responsável por:

- Ler eventos JSON do buffer
- Enviar payload para modelo local via Ollama API
- Classificar tráfego como:
  - `NORMAL`
  - `ATAQUE` (XSS, SQLi, Exploit, Flood, Scan)
- Gerar decisão estruturada
- Acionar bloqueio via feedback loop

---

## 🤖 Inteligência Artificial

Modelo utilizado:

- `qwen2.5-coder:3b` (via Ollama)

Função da IA:

- Análise semântica de tráfego
- Classificação de padrões suspeitos
- Geração de resposta estruturada

---

## 📂 Estrutura do Projeto


.
├── sentinela.py # Captura e geração de eventos de rede
├── auditoria.py # IA que analisa os eventos
├── README.md
└── /tmp/traffic_buffer # Pipeline de eventos (runtime)


---

## 🚀 Como Executar

### 1. Iniciar a IA local (Ollama)

```bash
ollama run qwen2.5-coder:3b
2. Rodar o Sentinela
sudo python3 sentinela.py
3. Rodar o analisador de IA
python3 auditoria.py
📡 Fluxo de Dados
Pacotes de rede são capturados
Convertidos em eventos JSON
Salvos no buffer /tmp/traffic_buffer
IA analisa cada evento
Sistema classifica como NORMAL ou ATAQUE
IPs suspeitos são adicionados ao feedback de bloqueio
🔥 Exemplo de Evento
{
  "ip": "192.168.1.50",
  "size": 512,
  "summary": "IP / TCP packet",
  "timestamp": 1720000000.123
}
🧪 Exemplo de Saída da IA
{
  "tipo": "ATAQUE",
  "categoria": "SQLi",
  "confianca": 0.92
}
🧠 Objetivo do Projeto

Este projeto simula um:

🔥 IDS híbrido com inteligência artificial local

Com foco em:

aprendizado de segurança de rede
detecção de intrusão
integração com LLMs locais
arquitetura de pipeline de eventos
⚠️ Aviso

Este projeto é experimental e deve ser utilizado apenas em ambientes controlados (laboratório / VM).

👨‍💻 Autor

Joelson Angelo
Cybersecurity & Systems Development


---

# 🚀 Agora o próximo passo

Depois de colar isso:

```bash
git add README.md
git commit -m "docs: update architecture and system pipeline description"
git push
💣 Resultado final

Seu GitHub vai ficar com:

projeto técnico explicado
arquitetura clara
fluxo visual
stack moderna (IA + IDS + Linux)
